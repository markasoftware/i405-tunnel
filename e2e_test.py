#!/usr/bin/env python3

# As of time of writing this is the only ai-generated part of I405, i promise :|
# it really shows lol

import subprocess
import shlex
import tempfile
import time
import os
import json
import re
import sys
import signal
from typing import Any

SERVER_NS: str = "i405-server"
CLIENT_NS: str = "i405-client"
SERVER_VETH: str = "veth-server"
CLIENT_VETH: str = "veth-client"

# TODO check if these are routable before the test starts, which would indicate conflicts with the
# existing system configuration.
SERVER_VETH_IP: str = "192.168.99.0"
CLIENT_VETH_IP: str = "192.168.99.1"
SERVER_PORT: int = 1405

SERVER_TUN_IP: str = "192.168.100.0"
CLIENT_TUN_IP: str = "192.168.100.1"

PACKET_INTERVAL_MS = 100
PASSWORD = "password"

I405_BINARY_PATH = "./target/debug/i405-tunnel"
I405_ENV = {"RUST_BACKTRACE": "1"} | os.environ

IPERF_TIMEOUT_SECS = 10

# we run our tests across all poll modes, and use this global variable to keep track of which one is
# currently set
global_poll_mode: str = "undefined"

# so we can terminate everything when we clean up
all_popens: list[subprocess.Popen[bytes]] = []

def default_client_args() -> dict[str, str]:
    global global_poll_mode
    return {
        "peer": f"{SERVER_VETH_IP}:{SERVER_PORT}",
        "poll-mode": global_poll_mode,
        "password": PASSWORD,
        "tun-ipv4": f"{CLIENT_TUN_IP}/24",
        "tun-name": "i405-client-tun",
        "outgoing-packet-interval": f"{PACKET_INTERVAL_MS}ms",
        "incoming-packet-interval": f"{PACKET_INTERVAL_MS}ms",
    }

def default_server_args() -> dict[str, str]:
    global global_poll_mode
    return {
        "poll-mode": global_poll_mode,
        "password": PASSWORD,
        "tun-ipv4": f"{SERVER_TUN_IP}/24",
        "tun-name": "i405-server-tun",
    }

def run_command(command: list[str], check: bool = True, capture_output: bool = False, text=False, **kwargs):
    """Helper to run shell commands."""
    print(f"Running: {shlex.join(command)}")
    try:
        result = subprocess.run(command, check=check, capture_output=capture_output, text=text, **kwargs)
        if capture_output:
            print("Stdout:\n", result.stdout)
            print("Stderr:\n", result.stderr)
        return result
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Error running {shlex.join(command)}, output: {e.output}") from e

def run_command_ns(namespace: str, command: list[str], check: bool = True, capture_output: bool = False, text: bool = False, **kwargs: Any) -> subprocess.CompletedProcess:
    """Helper to run shell commands within a network namespace."""
    ns_command: list[str] = ["ip", "netns", "exec", namespace] + command
    return run_command(ns_command, check=check, capture_output=capture_output, text=text, **kwargs)

def cleanup() -> None:
    """Clean up network namespaces and interfaces."""
    shutdown(*all_popens)
    print("Cleaning up network configuration...")
    # Use stderr=subprocess.DEVNULL to suppress "Cannot remove..." errors if they don't exist
    run_command(["ip", "netns", "del", SERVER_NS], check=False, stderr=subprocess.DEVNULL)
    run_command(["ip", "netns", "del", CLIENT_NS], check=False, stderr=subprocess.DEVNULL)
    # Veth pairs in the bridge namespace are automatically cleaned up when the namespace is deleted.
    print("Cleanup complete.")

def dict_to_args(d: dict[str, str | None]) -> list[str]:
    result: list[str] = []
    for key, value in d.items():
        if value is not None:
            result.append(f"--{key}")
            result.append(value)
    return result

def launch_client(cli_overrides: dict[str, str | None] | None = None) -> subprocess.Popen[bytes]:
    global all_popens
    if cli_overrides is None:
        cli_overrides = {}
    args = dict_to_args(default_client_args() | cli_overrides)
    cli = ["ip", "netns", "exec", CLIENT_NS, I405_BINARY_PATH, "client", *args]
    print(f"Launching client: {shlex.join(cli)}")
    result = subprocess.Popen(cli, env=I405_ENV)
    all_popens.append(result)
    return result

def launch_server(cli_overrides: dict[str, str | None] | None = None) -> subprocess.Popen[bytes]:
    global all_popens
    if cli_overrides is None:
        cli_overrides = {}
    args = dict_to_args(default_server_args() | cli_overrides)
    cli = ["ip", "netns", "exec", SERVER_NS, I405_BINARY_PATH, "server", *args]
    print(f"Launching server: {shlex.join(cli)}")
    result = subprocess.Popen(cli, env=I405_ENV)
    all_popens.append(result)
    return result

def shutdown(*popens: subprocess.Popen):
    for popen in popens:
        if popen.poll() is None:
            print(f"SIGTERM i405 instance w/ pid {popen.pid}")
            popen.terminate()
            time.sleep(0.25)
            if popen.poll() is None:
                print(f"Pid {popen.pid} did not exit cleanly, sending SIGKILL")
                popen.kill()
        if popen.returncode != 0:
            raise AssertionError(f"Pid {popen.pid} shut down with nonzero exit code {popen.returncode}")

def assert_ping():
    """
    Send two pings over the tunnel, pass if both succeed and take the expected amount of time (not
    too slow, not too fast)
    """
    ping_cmd = ["ping", "-c1", "-w1", SERVER_TUN_IP]
    first_ping_result = run_command_ns(CLIENT_NS, ping_cmd, capture_output=True, text=True)
    second_ping_result = run_command_ns(CLIENT_NS, ping_cmd, capture_output=True, text=True)
    ping_times_ms: list[float] = []
    for ping_result in first_ping_result, second_ping_result:
        match = re.search(r"time=(\d+\.?\d+)\s*ms", ping_result.stdout)
        if match:
            ping_times_ms.append(float(match.group(1)))
        else:
            raise RuntimeError(f"Could not extract ping time from output: {ping_result.stdout}")

    longest_ping_time = max(*ping_times_ms)
    # TODO there ight be a plausible reason for it to be shorter than the min here
    assert PACKET_INTERVAL_MS / 2 <= longest_ping_time <= PACKET_INTERVAL_MS * 3, f"Ping time out of range: {longest_ping_time}"

class TcpPerformanceTester:
    def __init__(self, upload: bool, download: bool, timeout: int):
        assert upload or download, 'must specify either upload or download'

        self.upload = upload
        self.download = download
        self.timeout = timeout
        self.start_time = time.time()
        # Start iperf server in server namespace. It will exit after one connection.
        iperf_server_cmd = ["ip", "netns", "exec", SERVER_NS, "iperf3", "-s", "-1"]
        print(f"Running: {shlex.join(iperf_server_cmd)}")
        self.iperf_server_process = subprocess.Popen(iperf_server_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        all_popens.append(self.iperf_server_process)
        time.sleep(0.5) # give server time to start

        iperf_client_cmd = ["ip", "netns", "exec", CLIENT_NS, "iperf3", "-c", SERVER_TUN_IP, "--json", "-t", str(timeout)]
        if download:
            if upload:
                iperf_client_cmd.append("--bidir")
            else:
                iperf_client_cmd.append("--reverse")

        print(f"Running: {shlex.join(iperf_client_cmd)}")
        self.iperf_client_process = subprocess.Popen(iperf_client_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        all_popens.append(self.iperf_client_process)

    # sleep until n seconds before the end of the test
    def sleep_until_secs_left(self, n: int):
        assert n < self.timeout, "n too large"
        time.sleep(time.time() + self.timeout - n)

    # return upload and download speeds (if requested)
    def finish(self) -> tuple[float | None, float | None, float]:
        iperf_client_stdout, iperf_client_stderr = self.iperf_client_process.communicate(timeout=self.timeout+5)
        all_popens.remove(self.iperf_client_process)
        if self.iperf_client_process.returncode != 0:
            raise RuntimeError(f"iperf3 nonzero exit code: {self.iperf_client_process.returncode}. Stdout: {iperf_client_stdout}, Stderr: {iperf_client_stderr}")
        _ = self.iperf_server_process.wait(0.5)
        all_popens.remove(self.iperf_server_process)
        iperf_output = json.loads(iperf_client_stdout)
        if 'error' in iperf_output:
            raise RuntimeError(f"iperf3 client error: {iperf_output['error']}")

        upload_speed = None
        download_speed = None
        max_rtt_us = 0
        for stream in iperf_output['end']['streams']:
            max_rtt_us = max(max_rtt_us, stream['sender']['max_rtt'])
        if self.upload:
            upload_speed = iperf_output['end']['sum_sent']['bits_per_second']/8
        if self.download:
            if self.upload:
                download_speed = iperf_output['end']['sum_received_bidir_reverse']['bits_per_second']/8
            else:
                download_speed = iperf_output['end']['sum_received']['bits_per_second']/8

        print(f"Iperf test done. UL:{upload_speed} DL:{download_speed} RTT:{max_rtt_us}us")
        return upload_speed, download_speed, max_rtt_us

def setup_network() -> None:
    print("Setting up netns-es and veths")

    # Create Network Namespaces
    run_command(["ip", "netns", "add", SERVER_NS])
    run_command(["ip", "netns", "add", CLIENT_NS])

    # Configure loopback interface in each namespace
    run_command_ns(SERVER_NS, ["ip", "link", "set", "dev", "lo", "up"])
    run_command_ns(CLIENT_NS, ["ip", "link", "set", "dev", "lo", "up"])

    # Create and Configure Veth Pairs for Server NS
    run_command(["ip", "link", "add", "name", CLIENT_VETH, "type", "veth", "peer", "name", SERVER_VETH])
    run_command(["ip", "link", "set", CLIENT_VETH, "netns", CLIENT_NS])
    run_command(["ip", "link", "set", SERVER_VETH, "netns", SERVER_NS])
    run_command_ns(SERVER_NS, ["ip", "addr", "add", f"{SERVER_VETH_IP}/24", "dev", SERVER_VETH])
    run_command_ns(SERVER_NS, ["ip", "link", "set", "dev", SERVER_VETH, "up"])
    run_command_ns(CLIENT_NS, ["ip", "addr", "add", f"{CLIENT_VETH_IP}/24", "dev", CLIENT_VETH])
    run_command_ns(CLIENT_NS, ["ip", "link", "set", "dev", CLIENT_VETH, "up"])

    print("Network namespaces set up")

def main() -> None:
    global global_poll_mode

    # Ensure we are running as root
    if os.geteuid() != 0:
        print("Please run this script with sudo.")
        sys.exit(1)


    # Register cleanup on exit signals
    signal.signal(signal.SIGINT, lambda sig, frame: (cleanup(), sys.exit(1)))
    signal.signal(signal.SIGTERM, lambda sig, frame: (cleanup(), sys.exit(1)))

    try:
        cleanup() # Ensure a clean state before starting
        setup_network()

        if len(sys.argv) > 1:
            if sys.argv[1] == 'debug':
                global_poll_mode = sys.argv[2]
                launch_server()
                launch_client()
                print(f"Debug mode: I405 running between network namespaces {CLIENT_NS} and {SERVER_NS} until interrupted.")
                while True:
                    time.sleep(60)
            else:
                raise RuntimeError("Invalid command line. Usage: ./e2e_test.py [debug spinny|sleepy]")

        # default: run tests
        else:
            for global_poll_mode in "sleepy", "spinny":
                print(f"About to test in poll-mode: {global_poll_mode}")
                basic_test()
                reconnect_test()
                monitor_packets_test()
                tcp_throughput_test()

        print()
        print("End-to-end test completed without error.")
        print()

    finally:
        cleanup() # Always clean up network namespaces and interfaces

def basic_test():
    print()
    print("E2E TEST: Basic test")
    print()
    server = launch_server()
    client = launch_client()
    time.sleep(0.25)
    assert_ping()

    shutdown(client, server)

def reconnect_test():
    """Can both sides reconnect to the other after a disconnection?"""
    print()
    print("E2E TEST: Reconnect test")
    print()
    server = launch_server()
    client = launch_client()
    time.sleep(0.25)
    assert_ping()
    shutdown(client)
    client = launch_client()
    time.sleep(0.25)
    assert_ping()
    shutdown(server)
    server = launch_server()
    # will have to increase this:
    time.sleep(1.25)
    assert_ping()

    shutdown(client, server)

def tcp_throughput_test():
    print()
    print("E2E TEST: TCP throughput test")
    print()
    server = launch_server()
    client = launch_client({
        "outgoing-packet-interval": None,
        "incoming-packet-interval": None,
        "outgoing-speed": "100k",
        "incoming-speed": "100k",
    })
    time.sleep(0.25)
    tester = TcpPerformanceTester(True, True, IPERF_TIMEOUT_SECS)
    upload_speed, download_speed, max_rtt_us = tester.finish()
    # trust me, i wish the lower bound here were higher :|
    assert 50_000 < upload_speed < 100_000
    assert 50_000 < download_speed < 100_000
    assert 0 < max_rtt_us < 100_000

    tester = TcpPerformanceTester(True, False, IPERF_TIMEOUT_SECS)
    upload_speed, _, max_rtt_us = tester.finish()

    # the speed is reliably higher when we're not pushing both directions at the same time.
    # Honestly, that's a bit worrying, but I'm willing to chalk it up to bufferbloat on the acks for
    # now :| I've observed it being higher than 100,000 in at least one case, maybe due to socket
    # buffer? idk man.
    assert 80_000 < upload_speed < 100_000
    assert 0 < max_rtt_us < 100_000

    shutdown(client, server)

def monitor_packets_test():
    print()
    print("E2E TEST: Monitor packets")
    print()

    # create temp dir
    with tempfile.TemporaryDirectory() as monitor_packets_dir:
        server = launch_server()
        client = launch_client({
            "monitor-packets": monitor_packets_dir,
        })

        time.sleep(1)

        shutdown(client, server)
        # check that exactly one subdirectory was created
        subdirs = [d for d in os.listdir(monitor_packets_dir) if os.path.isdir(os.path.join(monitor_packets_dir, d))]
        assert len(subdirs) == 1, f"Expected exactly one subdirectory in {monitor_packets_dir}, found {len(subdirs)}: {subdirs}"
        # check that the subdirectory contains exactly client_to_server.csv and server_to_client.csv
        subdir_path = os.path.join(monitor_packets_dir, subdirs[0])
        files = os.listdir(subdir_path)
        expected_files = {"client_to_server.csv", "server_to_client.csv"}
        assert set(files) == expected_files, f"Expected files {expected_files} in {subdir_path}, found {set(files)}"
        # Check that the files each have at least 10 rows, where first row is a header, and
        # remaining rows have three comma-separated numbers. Thanks github copilot
        for filename in files:
            file_path = os.path.join(subdir_path, filename)
            with open(file_path, 'r') as f:
                lines = f.readlines()
                assert len(lines) >= 10, f"Expected at least 10 lines in {file_path}, found {len(lines)}"
                for line in lines[1:]:
                    parts = line.strip().split(',')
                    assert len(parts) == 3, f"Expected 3 comma-separated values in {line.strip()} from {file_path}, found {len(parts)}"
                    for part in parts:
                        assert re.match(r'^\d+$', part), f"Expected numeric value in {part} from {file_path}"

if __name__ == "__main__":
    main()
