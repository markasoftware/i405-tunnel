use std::time::Duration;

use crate::wire_config::{MIN_DEFAULT_TIMEOUT, MIN_DEFAULT_TIMEOUT_PACKETS};

use clap::{Arg, ArgAction, ArgGroup, ArgMatches, Command, value_parser};
use declarative_enum_dispatch::enum_dispatch;
use humantime::format_duration;

const DEFAULT_TUN_NAME: &str = "tun-i405";
// TODO ensure there are no issues when this is greater than the inter-packet interval
const DEFAULT_FINALIZE_DELTA: &str = "1ms";

trait EzClap {
    // TODO consider combining to_args and to_groups
    fn to_args() -> Vec<Arg>;
    fn to_groups() -> Vec<ArgGroup> {
        Vec::new()
    }
    fn from_match(matches: &ArgMatches) -> Self;
}

pub(crate) struct WireIntervalCli {
    pub(crate) average_interval: AverageWireIntervalCli,
    pub(crate) jitter: Option<u64>,
}

pub(crate) enum AverageWireIntervalCli {
    Fixed(u64), // fixed interval in ns
    Rate(u64),  // bytes per second
}

pub(crate) struct WireConfigCli {
    pub(crate) outgoing_packet_length: Option<u64>,
    pub(crate) outgoing_finalize_delta: u64,
    pub(crate) outgoing_interval: WireIntervalCli,
    pub(crate) client_timeout: Option<Duration>,
    pub(crate) incoming_packet_length: Option<u64>,
    pub(crate) incoming_finalize_delta: u64,
    pub(crate) incoming_interval: WireIntervalCli,
    pub(crate) server_timeout: Option<Duration>,
}

impl EzClap for WireConfigCli {
    fn to_args() -> Vec<Arg> {
        vec![
            Arg::new("outgoing_packet_length")
                .long("outgoing-packet-length")
                .visible_alias("up-packet-length")
                .value_parser(value_parser!(bytesize::ByteSize))
                .help("Fixed upload packet length, in bytes. This is the ultimate size of the IP packets that will be sent over the network, not the encrypted I405 payload. See also --tun-mtu, which is different, and permitted to even be larger than the packet length! (in that case, the larger packets will be fragmented across I405 packets -- but that's a typical part of I405's operation anyway)"),
            Arg::new("outgoing_bytes_per_second")
                .long("outgoing-speed")
                .visible_alias("up-speed")
                .value_parser(value_parser!(bytesize::ByteSize))
                .help("Bytes per second to upload. This is the \"outer\" bandwidth measured by the sum of IP packet lengths; the actual amount of data that can be transmitted inside the tunnel is smaller (at the time of writing, the overhead is 5-10%). Typical suffixes are supported, eg, 5k. When specified, the packet interval is determined automatically from this and the upload packet length."),
            Arg::new("outgoing_packet_interval")
                .long("outgoing-packet-interval")
                .visible_alias("up-packet-interval")
                .value_parser(humantime::parse_duration)
                .help("Fixed upload packet interval. Eg \"8.5ms\""),
            Arg::new("outgoing_packet_jitter")
                .long("outgoing-packet-jitter")
                .visible_alias("up-packet-jitter")
                .value_parser(humantime::parse_duration)
                .help("Max jitter around the upload packet interval. The interval will never be less than the outgoing packet interval minus the jitter, nor greater than the interval plus the jitter. By default, the jitter is 25% of the packet interval. (However, if you explicitly specify a jitter, it's an absolute value, not a percentage of the packet interval).\n\nThe distribution of inter-packet intervals is a bit weird: With about 92.5% probability, the packet interval will be uniformly random within [interval - jitter*0.75, interval + jitter*0.75], and with about 7.5% probability, the packet interval will be in the remaining part of [interval-jitter, interval+jitter]. The default max jitter is 25% of the outgoing packet interval."),
            Arg::new("outgoing_finalize_delta")
                .long("outgoing-finalize-delta")
                .visible_alias("up-finalize-delta")
                .default_value(DEFAULT_FINALIZE_DELTA)
                .value_parser(humantime::parse_duration)
                .help("How long to finalize the contents of a packet to be sent before actually sending it. If too short, then packets may frequently be delayed and not sent at the intended times. This is most likely to happen under system load, and those delayed packets could indicate to an attacker that your system is under load. Warnings are logged whenever this happens, so increase this value if you see those warnings frequently."),
            Arg::new("client_timeout")
                .long("client-timeout")
                .value_parser(humantime::parse_duration)
                .help(format!("The client will disconnect if no packet is received from the server within this amount of time. Defaults to max({}, {MIN_DEFAULT_TIMEOUT_PACKETS}*incoming_packet_interval), ie, will disconnect after at least 10 seconds have elapsed and at least {MIN_DEFAULT_TIMEOUT_PACKETS} packets are dropped/delayed.", format_duration(MIN_DEFAULT_TIMEOUT))),
            Arg::new("incoming_packet_length")
                .long("incoming-packet-length")
                .visible_alias("down-packet-length")
                .value_parser(value_parser!(bytesize::ByteSize))
                .help("Fixed download packet length, in bytes"),
            Arg::new("incoming_bytes_per_second")
                .long("incoming-speed")
                .visible_alias("down-speed")
                .value_parser(value_parser!(bytesize::ByteSize))
                .help("See the documentation for --outgoing-speed"),
            Arg::new("incoming_packet_interval")
                .long("incoming-packet-interval")
                .visible_alias("down-packet-interval")
                .value_parser(humantime::parse_duration)
                .help("Fixed download packet interval, in nanoseconds"),
            Arg::new("incoming_packet_jitter")
                .long("incoming-packet-jitter")
                .value_parser(humantime::parse_duration)
                .help("See the documentation for --outgoing-packet-jitter"),
            Arg::new("incoming_finalize_delta")
                .long("incoming-finalize-delta")
                .visible_alias("down-finalize-delta")
                .default_value(DEFAULT_FINALIZE_DELTA)
                .value_parser(humantime::parse_duration)
                // TODO make sure we print warnings for delayed finalization on the server, on the
                // client (via statistics).
                .help("See the documentation for --outgoing-finalize-delta"),
            Arg::new("server_timeout")
                .long("server-timeout")
                .value_parser(humantime::parse_duration)
                .help("See --client-timeout"),
        ]
    }

    fn to_groups() -> Vec<ArgGroup> {
        vec![
            ArgGroup::new("outgoing_rate")
                .args(["outgoing_packet_interval", "outgoing_bytes_per_second"])
                .required(true),
            ArgGroup::new("incoming_rate")
                .args(["incoming_packet_interval", "incoming_bytes_per_second"])
                .required(true),
        ]
    }

    fn from_match(matches: &ArgMatches) -> Self {
        let parse_interval = |in_or_out| -> WireIntervalCli {
            let jitter = matches
                .get_one::<Duration>(&format!("{in_or_out}_packet_jitter"))
                .map(|jitter| {
                    jitter
                        .as_nanos()
                        .try_into()
                        .expect("Don't put jitter longer than hundreds of years")
                });
            let average_interval = match (
                matches.get_one::<Duration>(&format!("{in_or_out}_packet_interval")),
                matches.get_one::<bytesize::ByteSize>(&format!("{in_or_out}_bytes_per_second")),
            ) {
                (Some(interval), None) => AverageWireIntervalCli::Fixed(
                    interval
                        .as_nanos()
                        .try_into()
                        .expect("Don't put intervals longer than hundreds of years"),
                ),
                (None, Some(bytes_per_second)) => {
                    AverageWireIntervalCli::Rate(bytes_per_second.as_u64())
                }
                _ => unreachable!(
                    "Clap should enforce that either interval or bytes per second is set."
                ),
            };
            WireIntervalCli {
                average_interval,
                jitter,
            }
        };
        WireConfigCli {
            outgoing_packet_length: matches
                .get_one::<bytesize::ByteSize>("outgoing_packet_length")
                .map(|x| x.as_u64()),
            outgoing_interval: parse_interval("outgoing"),
            outgoing_finalize_delta: matches
                .get_one::<Duration>("outgoing_finalize_delta")
                .unwrap()
                .as_nanos()
                .try_into()
                .unwrap(),
            client_timeout: matches.get_one::<Duration>("client_timeout").cloned(),
            incoming_packet_length: matches
                .get_one::<bytesize::ByteSize>("incoming_packet_length")
                .map(|x| x.as_u64()),
            incoming_interval: parse_interval("incoming"),
            incoming_finalize_delta: matches
                .get_one::<Duration>("incoming_finalize_delta")
                .unwrap()
                .as_nanos()
                .try_into()
                .unwrap(),
            server_timeout: matches.get_one::<Duration>("server_timeout").cloned(),
        }
    }
}

pub(crate) struct CommonConfigCli {
    pub(crate) pre_shared_key: Vec<u8>,
    pub(crate) listen_addr: Option<String>,
    pub(crate) tun_name: String,
    pub(crate) tun_mtu: Option<u16>,
    pub(crate) tun_ipv4: Option<String>,
    pub(crate) tun_ipv6: Option<String>,
    pub(crate) no_tun_qdisc: bool,
    pub(crate) no_sched_fifo: bool,
    pub(crate) outgoing_send_deviation_stats: Option<Duration>,
    pub(crate) poll_mode: PollMode,
}

pub(crate) enum PollMode {
    Sleepy,
    Spinny,
}

impl EzClap for CommonConfigCli {
    fn to_args() -> Vec<Arg> {
        vec![
            Arg::new("pre_shared_key")
                .long("password")
                .visible_alias("pre-shared-key")
                .value_parser(value_parser!(Vec<u8>))
                .required(true)
                .help("Encryption password that both client and server must share"),
            Arg::new("listen_addr")
                .long("listen-addr")
                .help("Address and port to listen on. Default for server is 0.0.0.0:1405, client is 0.0.0.0:0 (the OS chooses the port)"),
	    Arg::new("tun_name")
		.long("tun-name")
		.default_value(DEFAULT_TUN_NAME)
		.help("Name of the TUN device to use or create"),
            Arg::new("tun_mtu")
                .long("tun-mtu")
                .value_parser(value_parser!(u16))
                .help("MTU for the TUN device. It's okay for this to be larger than the packet length; I405 will fragment and reassemble packets as necessary. By default, let the system decide (usually 1500).\n\nI405 does not make any attempt to calculate the max TUN MTU such that the wrapped packets can also be sent out in one I405 packet; setting tun mtu to be substantially less than 1500 (eg, 1400) should be enough, and may improve latency a bit. However, because I405 tries to pack multiple wrapped packets into I405 packets, even a smaller MTU does not guarantee that sent packets will not be fragmented by I405."),
	    Arg::new("tun_ipv4")
		.long("tun-ipv4")
		.help("IPv4 address (optionally with netmask) to automatically assign and route to the TUN device."),
            Arg::new("tun_ipv6")
                .long("tun-ipv6")
                .help("IPv6 address (optionall with netmask) to automatically assign and route to the TUN device."),
            Arg::new("no_tun_qdisc")
                .long("no-tun-qdisc")
                .action(ArgAction::SetTrue)
                .help("By default, I405 will reconfigure the qdisc on the TUN interface to improve TCP performance. Specify this option if you are going to configure the qdisc manually."),
            Arg::new("outgoing_send_deviation_stats")
                .long("outgoing-send-deviation-stats")
                .value_parser(humantime::parse_duration)
                .help("If set, keep track of actual vs. expected outgoing send timestamps for packets and print a report this often (eg, 10s)"),
            Arg::new("poll_mode")
                .long("poll-mode")
                .value_parser(["sleepy", "spinny"])
                // TODO consider changing to spinny:
                .default_value("sleepy")
                .help("Control how we poll/wait for network events. The default is `sleepy`, which uses the OS' timers to schedule wakeups whenthere is nothing to do immediately (eg, to wait until the next time that an outgoing packet is scheduled to be sent). This is power-efficient and keeps CPU usage low. However, the time it takes to wake up after a sleep varies under system load, so outgoing packet timings may sligthly vary based on system load and leak information about whether the system is busy. In `spinny` mode, spin loops/busy loops are used for timing, which keeps the CPU hot and has more consistent wake-up times, at the cost of 100% CPU usage on one core. In spinny mode, you'll also probably want to "),
            Arg::new("no_sched_fifo")
                .long("no-sched-fifo")
                .action(ArgAction::SetTrue)
                .help("I405 by default sets the scheduling policy its main thread to SCHED_FIFO. Specify this option to use the default scheduling policy instead. Don't specify this option unless you really know what you're doing; SCHED_FIFO is the single most helpful thing to improve the precision of the times at which I405 sends outgoing packets!"),
        ]
    }

    fn from_match(matches: &ArgMatches) -> Self {
        CommonConfigCli {
            pre_shared_key: matches
                .get_one::<Vec<u8>>("pre_shared_key")
                .unwrap()
                .clone(),
            // TODO rename to bind_addr so it makes more sense on the client?
            listen_addr: matches.get_one::<String>("listen_addr").cloned(),
            tun_name: matches.get_one::<String>("tun_name").unwrap().clone(),
            tun_mtu: matches.get_one::<u16>("tun_mtu").cloned(),
            tun_ipv4: matches.get_one::<String>("tun_ipv4").cloned(),
            tun_ipv6: matches.get_one::<String>("tun_ipv6").cloned(),
            no_tun_qdisc: matches.get_one::<bool>("no_tun_qdisc").unwrap().clone(),
            no_sched_fifo: matches.get_one::<bool>("no_sched_fifo").unwrap().clone(),
            outgoing_send_deviation_stats: matches
                .get_one::<Duration>("outgoing_send_deviation_stats")
                .cloned(),
            poll_mode: match matches.get_one::<String>("poll_mode").unwrap().as_ref() {
                "sleepy" => PollMode::Sleepy,
                "spinny" => PollMode::Spinny,
                other => {
                    panic!("\"{other}\" is not a valid poll mode -- try \"sleepy\" or \"spinny\"")
                }
            },
        }
    }
}

pub(crate) struct ClientConfigCli {
    pub(crate) common_configuration: CommonConfigCli,
    pub(crate) wire_configuration: WireConfigCli,
    pub(crate) peer: String,
}

impl EzClap for ClientConfigCli {
    fn to_args() -> Vec<Arg> {
        let mut result = Vec::new();
        result.extend(CommonConfigCli::to_args());
        result.extend(WireConfigCli::to_args());
        result.push(
            Arg::new("peer")
                .long("peer")
                .visible_alias("server")
                .required(true)
                .help("Address or hostname (including port) of the server to connect to"),
        );
        result
    }

    fn to_groups() -> Vec<ArgGroup> {
        let mut result = Vec::new();
        result.extend(CommonConfigCli::to_groups());
        result.extend(WireConfigCli::to_groups());
        result
    }

    fn from_match(matches: &ArgMatches) -> Self {
        Self {
            common_configuration: CommonConfigCli::from_match(matches),
            wire_configuration: WireConfigCli::from_match(matches),
            peer: matches.get_one::<String>("peer").unwrap().clone(),
        }
    }
}

impl ContainsCommonConfigCli for ClientConfigCli {
    fn common_config_cli(&self) -> &CommonConfigCli {
        &self.common_configuration
    }
}

pub(crate) struct ServerConfigCli {
    pub(crate) common_configuration: CommonConfigCli,
}

impl EzClap for ServerConfigCli {
    fn to_args() -> Vec<Arg> {
        CommonConfigCli::to_args()
    }

    fn to_groups() -> Vec<ArgGroup> {
        CommonConfigCli::to_groups()
    }

    fn from_match(matches: &ArgMatches) -> Self {
        Self {
            common_configuration: CommonConfigCli::from_match(matches),
        }
    }
}

impl ContainsCommonConfigCli for ServerConfigCli {
    fn common_config_cli(&self) -> &CommonConfigCli {
        &self.common_configuration
    }
}

enum_dispatch! {
    pub(crate) trait ContainsCommonConfigCli {
        fn common_config_cli(&self) -> &CommonConfigCli;
    }

    pub(crate) enum ConfigCli {
        Client(ClientConfigCli),
        Server(ServerConfigCli),
    }
}

fn client_command() -> Command {
    Command::new("client")
        .args(ClientConfigCli::to_args())
        .groups(ClientConfigCli::to_groups())
}

fn server_command() -> Command {
    Command::new("server")
        .args(ServerConfigCli::to_args())
        .groups(ServerConfigCli::to_groups())
}

fn main_command() -> Command {
    Command::new("I-405")
        .subcommand(client_command())
        .subcommand(server_command())
        .subcommand_required(true)
}

pub(crate) fn parse_args() -> ConfigCli {
    let top_level_matches = main_command().get_matches();
    match top_level_matches.subcommand() {
        Some(("client", matches)) => ConfigCli::Client(ClientConfigCli::from_match(matches)),
        Some(("server", matches)) => ConfigCli::Server(ServerConfigCli::from_match(matches)),
        _ => unreachable!(),
    }
}

// Aside: I think the Right Way to do options is have a struct which contains all the possible
// sources the option could have come from, and the value found in each spot (eg, CLI, config file,
// default value). Then there's a "get" method on each option, that tells you the effective value.
// This makes it much easier to merge configurations together, for example.
