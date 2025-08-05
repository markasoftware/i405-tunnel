use std::collections::HashMap;
use std::fs;
use std::process::{Child, Command, ExitCode, Stdio};
use std::thread;
use std::time::Duration;

use anyhow::bail;
use anyhow::{Context, Result};
use libtest_mimic::{Arguments, Trial};
use regex::Regex;
use serde_json::Value;

// Constants
const SERVER_NS: &str = "i405-e2e-server";
const CLIENT_NS: &str = "i405-e2e-client";
const SERVER_VETH: &str = "veth-server";
const CLIENT_VETH: &str = "veth-client";

const SERVER_VETH_IP: &str = "192.168.99.0";
const CLIENT_VETH_IP: &str = "192.168.99.1";
const SERVER_PORT: u16 = 1405;

const SERVER_TUN_IP: &str = "192.168.100.0";
const CLIENT_TUN_IP: &str = "192.168.100.1";

const PACKET_INTERVAL_MS: u32 = 100;
const PASSWORD: &str = "password";

// Is there any better way to integrate with the test infrastructure to get the actual binary built
// as part of the test? Is the binary even built at all as part of the test?
const I405_BINARY_PATH: &str = "./target/debug/i405-tunnel";
const IPERF_TIMEOUT_SECS: u32 = 10;

struct TestEnvironment {
    poll_mode: String,
    client: Option<Child>,
    server: Option<Child>,
}

impl TestEnvironment {
    fn new(poll_mode: impl ToString) -> Result<TestEnvironment> {
        // Ensure we are running as root
        if !nix::unistd::geteuid().is_root() {
            bail!("E2E test must be run with sudo (eg, sudo -E cargo test -- --ignored)");
        }

        let mut result = TestEnvironment {
            poll_mode: poll_mode.to_string(),
            client: None,
            server: None,
        };
        result.cleanup();
        setup_network()?;

        Ok(result)
    }

    fn shutdown_client(&mut self) -> Result<()> {
        log::debug!("shutting down client");
        if let Some(client) = std::mem::take(&mut self.client) {
            shutdown_child(client)
        } else {
            Ok(())
        }
    }

    fn shutdown_server(&mut self) -> Result<()> {
        log::debug!("shutting down server");
        if let Some(server) = std::mem::take(&mut self.server) {
            shutdown_child(server)
        } else {
            Ok(())
        }
    }

    fn launch_client(&mut self, cli_overrides: Option<HashMap<String, Option<String>>>) {
        let overrides = cli_overrides.unwrap_or_default();
        let mut args = default_client_args(self);
        for (k, v) in overrides {
            args.insert(k, v);
        }

        let arg_vec = dict_to_args(args);
        let mut cmd = Command::new("ip");
        cmd.args(["netns", "exec", CLIENT_NS, I405_BINARY_PATH, "client"]);
        cmd.args(&arg_vec);
        cmd.env("RUST_BACKTRACE", "1");

        log::info!(
            "Launching client: ip netns exec {} {} client {}",
            CLIENT_NS,
            I405_BINARY_PATH,
            arg_vec.join(" ")
        );

        self.client = Some(cmd.spawn().unwrap());
    }

    fn launch_server(&mut self, cli_overrides: Option<HashMap<String, Option<String>>>) {
        let overrides = cli_overrides.unwrap_or_default();
        let mut args = default_server_args(self);
        for (k, v) in overrides {
            args.insert(k, v);
        }

        let arg_vec = dict_to_args(args);
        let mut cmd = Command::new("ip");
        cmd.args(["netns", "exec", SERVER_NS, I405_BINARY_PATH, "server"]);
        cmd.args(&arg_vec);
        cmd.env("RUST_BACKTRACE", "1");

        log::info!(
            "Launching server: ip netns exec {} {} server {}",
            SERVER_NS,
            I405_BINARY_PATH,
            arg_vec.join(" ")
        );

        self.server = Some(cmd.spawn().unwrap());
    }

    fn cleanup(&mut self) {
        // shutdown processes
        let e_client = self.shutdown_client();
        let e_server = self.shutdown_server();

        // Clean up namespaces, ignore errors
        let _ = run_command(&["ip", "netns", "del", SERVER_NS], false);
        let _ = run_command(&["ip", "netns", "del", CLIENT_NS], false);

        e_client.expect("Error shutting down client");
        e_server.expect("Error shutting down server");
    }
}

impl Drop for TestEnvironment {
    fn drop(&mut self) {
        self.cleanup();
    }
}

fn shutdown_child(mut process: Child) -> Result<()> {
    if let Ok(Some(_)) = process.try_wait() {
        log::debug!("pid {} was already not running", process.id());
        return Ok(());
    }

    log::debug!("sending SIGTERM to pid {}", process.id());
    if let Err(e) = nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(process.id().try_into().unwrap()),
        nix::sys::signal::SIGTERM,
    ) {
        log::error!("Error sending SIGTERM: {e:?}");
    }
    std::thread::sleep(Duration::from_millis(250));
    match process.try_wait() {
        Ok(Some(status)) => {
            // If we try to shut down right after spawning a process, this can happen with
            // status.code() == None. Don't think about it too much.
            if !status.success() {
                bail!(
                    "pid {} shutdown with nonzero exit code after SIGTERM: {:?}",
                    process.id(),
                    status.code()
                );
            }
        }
        Ok(None) => {
            log::error!(
                "pid {} did not shutdown in response to SIGTERM, force killing",
                process.id()
            );
            if let Err(e) = process.kill() {
                bail!("Error sending SIGKILL: {e:?}");
            }
            bail!("Had to SIGKILL pid {}", process.id());
        }
        Err(e) => bail!("Error in try_wait for PID {}: {e:?}", process.id()),
    }
    Ok(())
}

fn default_client_args(env: &TestEnvironment) -> HashMap<String, Option<String>> {
    let mut args = HashMap::new();
    args.insert(
        "peer".to_string(),
        Some(format!("{}:{}", SERVER_VETH_IP, SERVER_PORT)),
    );
    args.insert("poll-mode".to_string(), Some(env.poll_mode.to_string()));
    args.insert("password".to_string(), Some(PASSWORD.to_string()));
    args.insert(
        "tun-ipv4".to_string(),
        Some(format!("{}/24", CLIENT_TUN_IP)),
    );
    args.insert("tun-name".to_string(), Some("i405-client-tun".to_string()));
    args.insert(
        "outgoing-packet-interval".to_string(),
        Some(format!("{}ms", PACKET_INTERVAL_MS)),
    );
    args.insert(
        "incoming-packet-interval".to_string(),
        Some(format!("{}ms", PACKET_INTERVAL_MS)),
    );
    args
}

fn default_server_args(env: &TestEnvironment) -> HashMap<String, Option<String>> {
    let mut args = HashMap::new();
    args.insert("poll-mode".to_string(), Some(env.poll_mode.to_string()));
    args.insert("password".to_string(), Some(PASSWORD.to_string()));
    args.insert(
        "tun-ipv4".to_string(),
        Some(format!("{}/24", SERVER_TUN_IP)),
    );
    args.insert("tun-name".to_string(), Some("i405-server-tun".to_string()));
    args
}

fn run_command(command: &[&str], check: bool) -> Result<std::process::Output> {
    log::info!("Running: {}", command.join(" "));
    let output = Command::new(command[0])
        .args(&command[1..])
        .output()
        .with_context(|| format!("Failed to execute command: {}", command.join(" ")))?;

    if check && !output.status.success() {
        bail!(
            "Command failed: {}, stderr: {}",
            command.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(output)
}

fn run_command_ns(namespace: &str, command: &[&str], check: bool) -> Result<std::process::Output> {
    let mut ns_command = vec!["ip", "netns", "exec", namespace];
    ns_command.extend(command);
    run_command(&ns_command, check)
}

fn dict_to_args(args: HashMap<String, Option<String>>) -> Vec<String> {
    let mut result = Vec::new();
    for (key, value) in args {
        if let Some(val) = value {
            result.push(format!("--{}", key));
            result.push(val);
        }
    }
    result
}

fn assert_ping() {
    let ping_cmd = ["ping", "-c1", "-w1", SERVER_TUN_IP];

    let first_ping = run_command_ns(CLIENT_NS, &ping_cmd, true).unwrap();
    let second_ping = run_command_ns(CLIENT_NS, &ping_cmd, true).unwrap();

    let re = Regex::new(r"time=(\d+\.?\d*)\s*ms").unwrap();
    let mut ping_times = Vec::new();

    for output in [first_ping, second_ping] {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(captures) = re.captures(&stdout) {
            let time_str = captures.get(1).unwrap().as_str();
            let time: f64 = time_str.parse().unwrap();
            ping_times.push(time);
        } else {
            panic!("Could not extract ping time from output: {}", stdout);
        }
    }

    let longest_ping_time = ping_times.iter().fold(0.0f64, |a, &b| a.max(b));
    let min_expected = PACKET_INTERVAL_MS as f64 / 2.0;
    let max_expected = PACKET_INTERVAL_MS as f64 * 3.0;

    assert!(
        min_expected <= longest_ping_time && longest_ping_time <= max_expected,
        "Ping time out of range: {} (expected between {} and {})",
        longest_ping_time,
        min_expected,
        max_expected
    );
}

struct TcpPerformanceTester {
    upload: bool,
    download: bool,
    timeout: u32,
}

impl TcpPerformanceTester {
    fn new(upload: bool, download: bool, timeout: u32) -> Self {
        assert!(
            upload || download,
            "Must specify at least one of upload or download"
        );

        Self {
            upload,
            download,
            timeout,
        }
    }

    fn finish(self) -> (Option<f64>, Option<f64>, f64) {
        // Start iperf server
        let mut iperf_server = Command::new("ip")
            .args(["netns", "exec", SERVER_NS, "iperf3", "-s", "-1"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();

        thread::sleep(Duration::from_millis(500)); // Give server time to start

        // Start iperf client
        let mut client_cmd = Command::new("ip");
        client_cmd.args([
            "netns",
            "exec",
            CLIENT_NS,
            "iperf3",
            "-c",
            SERVER_TUN_IP,
            "--json",
            "-t",
            &self.timeout.to_string(),
        ]);

        if self.download {
            if self.upload {
                client_cmd.arg("--bidir");
            } else {
                client_cmd.arg("--reverse");
            }
        }

        let output = client_cmd.output().unwrap();

        let _ = iperf_server.kill();
        let _ = iperf_server.wait();

        assert!(
            output.status.success(),
            "iperf3 client failed with exit code {:?}, stderr: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );

        let iperf_output: Value = serde_json::from_slice(&output.stdout).unwrap();

        if let Some(error) = iperf_output.get("error") {
            panic!("iperf3 client error: {}", error);
        }

        let mut upload_speed = None;
        let mut download_speed = None;
        let mut max_rtt_us: f64 = 0.0;

        if let Some(streams) = iperf_output["end"]["streams"].as_array() {
            for stream in streams {
                if let Some(rtt) = stream["sender"]["max_rtt"].as_f64() {
                    max_rtt_us = max_rtt_us.max(rtt);
                }
            }
        }

        if self.upload {
            upload_speed = iperf_output["end"]["sum_sent"]["bits_per_second"]
                .as_f64()
                .map(|bps| bps / 8.0);
        }

        if self.download {
            if self.upload {
                download_speed =
                    iperf_output["end"]["sum_received_bidir_reverse"]["bits_per_second"]
                        .as_f64()
                        .map(|bps| bps / 8.0);
            } else {
                download_speed = iperf_output["end"]["sum_received"]["bits_per_second"]
                    .as_f64()
                    .map(|bps| bps / 8.0);
            }
        }

        log::info!(
            "Iperf test done. UL:{:?} DL:{:?} RTT:{}us",
            upload_speed,
            download_speed,
            max_rtt_us
        );
        (upload_speed, download_speed, max_rtt_us)
    }
}

fn setup_network() -> Result<()> {
    log::debug!("Setting up netns-es and veths");

    // Create Network Namespaces
    run_command(&["ip", "netns", "add", SERVER_NS], true)?;
    run_command(&["ip", "netns", "add", CLIENT_NS], true)?;

    // Configure loopback interface in each namespace
    run_command_ns(SERVER_NS, &["ip", "link", "set", "dev", "lo", "up"], true)?;
    run_command_ns(CLIENT_NS, &["ip", "link", "set", "dev", "lo", "up"], true)?;

    // Create and Configure Veth Pairs
    run_command(
        &[
            "ip",
            "link",
            "add",
            "name",
            CLIENT_VETH,
            "type",
            "veth",
            "peer",
            "name",
            SERVER_VETH,
        ],
        true,
    )?;
    run_command(
        &["ip", "link", "set", CLIENT_VETH, "netns", CLIENT_NS],
        true,
    )?;
    run_command(
        &["ip", "link", "set", SERVER_VETH, "netns", SERVER_NS],
        true,
    )?;
    run_command_ns(
        SERVER_NS,
        &[
            "ip",
            "addr",
            "add",
            &format!("{}/24", SERVER_VETH_IP),
            "dev",
            SERVER_VETH,
        ],
        true,
    )?;
    run_command_ns(
        SERVER_NS,
        &["ip", "link", "set", "dev", SERVER_VETH, "up"],
        true,
    )?;
    run_command_ns(
        CLIENT_NS,
        &[
            "ip",
            "addr",
            "add",
            &format!("{}/24", CLIENT_VETH_IP),
            "dev",
            CLIENT_VETH,
        ],
        true,
    )?;
    run_command_ns(
        CLIENT_NS,
        &["ip", "link", "set", "dev", CLIENT_VETH, "up"],
        true,
    )?;

    log::debug!("Network namespaces set up");
    Ok(())
}

fn basic_test(env: &mut TestEnvironment) {
    env.launch_server(None);
    env.launch_client(None);
    thread::sleep(Duration::from_millis(250));
    assert_ping();
}

fn reconnect_test(env: &mut TestEnvironment) {
    env.launch_server(None);
    env.launch_client(None);
    thread::sleep(Duration::from_millis(250));
    assert_ping();

    // Shutdown client and restart
    env.shutdown_client().unwrap();
    env.launch_client(None);
    thread::sleep(Duration::from_millis(250));
    assert_ping();

    // Shutdown server and restart
    env.shutdown_server().unwrap();
    env.launch_server(None);
    thread::sleep(Duration::from_millis(1250));
    assert_ping();
}

fn tcp_throughput_test(env: &mut TestEnvironment) {
    env.launch_server(None);

    let mut client_overrides = HashMap::new();
    client_overrides.insert("outgoing-packet-interval".to_string(), None);
    client_overrides.insert("incoming-packet-interval".to_string(), None);
    client_overrides.insert("outgoing-speed".to_string(), Some("100k".to_string()));
    client_overrides.insert("incoming-speed".to_string(), Some("100k".to_string()));

    env.launch_client(Some(client_overrides));
    thread::sleep(Duration::from_millis(250));

    let tester = TcpPerformanceTester::new(true, true, IPERF_TIMEOUT_SECS);
    let (upload_speed, download_speed, max_rtt_us) = tester.finish();

    let upload = upload_speed.unwrap();
    let download = download_speed.unwrap();

    assert!(
        50_000.0 < upload && upload < 100_000.0,
        "Upload speed out of range (50_000, 100_000): {}",
        upload
    );
    assert!(
        50_000.0 < download && download < 100_000.0,
        "Download speed out of range (50_000, 100_000): {}",
        download
    );
    assert!(
        0.0 < max_rtt_us && max_rtt_us < 125_000.0,
        "RTT μs out of range (0, 125_000): {}",
        max_rtt_us
    );

    let tester = TcpPerformanceTester::new(true, false, IPERF_TIMEOUT_SECS);
    let (upload_speed, _, max_rtt_us) = tester.finish();
    let upload = upload_speed.unwrap();

    assert!(
        80_000.0 < upload && upload < 100_000.0,
        "Upload speed out of range (80_000, 100_000): {}",
        upload
    );
    assert!(
        0.0 < max_rtt_us && max_rtt_us < 125_000.0,
        "RTT μs out of range (0, 125_000): {}",
        max_rtt_us
    );
}

fn monitor_packets_test(env: &mut TestEnvironment) {
    let temp_dir = tempfile::tempdir().unwrap();
    let monitor_dir = temp_dir.path().to_str().unwrap();

    env.launch_server(None);

    let mut client_overrides = HashMap::new();
    client_overrides.insert("monitor-packets".to_string(), Some(monitor_dir.to_string()));
    env.launch_client(Some(client_overrides));

    thread::sleep(Duration::from_secs(1));
    // buf writer may not have written anything, we have to shut it down.
    env.shutdown_client().unwrap();

    // Check that exactly one subdirectory was created
    let entries: Vec<_> = fs::read_dir(monitor_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .collect();

    assert_eq!(entries.len(), 1);

    let subdir_path = entries[0].path();
    let files: Vec<_> = fs::read_dir(&subdir_path)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();

    let expected_files = ["outgoing.csv", "incoming.csv"];
    for expected in expected_files {
        assert!(files.contains(&expected.to_string()));
    }

    // Check file contents
    let re = Regex::new(r"^\d+,\d+,\d+$").unwrap();
    for filename in expected_files {
        let file_path = subdir_path.join(filename);
        let content = fs::read_to_string(&file_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        let min_lines = 5;

        assert!(
            lines.len() >= min_lines,
            "Not enough lines in monitor packets file"
        );

        for line in lines.iter().skip(1) {
            assert!(re.is_match(line));
        }
    }
}

fn collect_tests() -> Result<Vec<Trial>, Box<dyn std::error::Error>> {
    let mut tests = Vec::new();
    #[allow(clippy::type_complexity)]
    let test_fns: Vec<(&str, fn(&mut TestEnvironment))> = vec![
        ("basic_test", basic_test),
        ("reconnect_test", reconnect_test),
        ("tcp_throughput_test", tcp_throughput_test),
        ("monitor_packets_test", monitor_packets_test),
    ];

    for &poll_mode in &["sleepy", "spinny"] {
        for &(name, test_fn) in &test_fns {
            let test_name = format!("{}_{}", name, poll_mode);
            let trial = Trial::test(test_name, move || {
                // Initialize network environment (this handles sudo check, net namespaces, etc.)
                let mut env = TestEnvironment::new(poll_mode)?;
                test_fn(&mut env);
                Ok(())
            })
            .with_kind("e2e")
            .with_ignored_flag(true);
            tests.push(trial);
        }
    }

    Ok(tests)
}

fn main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let mut args = Arguments::from_args();
    // I'm not sure if the following affects other tests too. Burn that bridge when we get there.
    // (The "right" way is to use a mutex, though you have to be careful to continue when poisoned).
    args.test_threads = Some(1);

    let tests = collect_tests()?;

    Ok(libtest_mimic::run(&args, tests).exit_code())
}
