use std::time::Duration;

use clap::{Arg, ArgGroup, ArgMatches, Command, value_parser};
use declarative_enum_dispatch::enum_dispatch;

const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:1405";
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

pub(crate) enum WireInterval {
    Fixed(u64), // fixed interval in ns
    Rate(u64),  // bytes per second
}

pub(crate) struct WireConfiguration {
    pub(crate) outgoing_packet_length: Option<u64>,
    pub(crate) outgoing_finalize_delta: u64,
    pub(crate) outgoing_interval: WireInterval,
    pub(crate) incoming_packet_length: Option<u64>,
    pub(crate) incoming_finalize_delta: u64,
    pub(crate) incoming_interval: WireInterval,
}

impl EzClap for WireConfiguration {
    fn to_args() -> Vec<Arg> {
        vec![
            Arg::new("outgoing_packet_length")
                .long("outgoing-packet-length")
                .visible_alias("up-packet-length")
                .value_parser(value_parser!(bytesize::ByteSize))
                .help("Fixed upload packet length, in bytes"),
            Arg::new("outgoing_packet_interval")
                .long("outgoing-packet-interval")
                .visible_alias("up-packet-interval")
                .value_parser(humantime::parse_duration)
                .help("Fixed upload packet interval, in nanoseconds"),
            Arg::new("outgoing_bytes_per_second")
                .long("outgoing-bytes-per-second")
                .visible_alias("outgoing-speed")
                .visible_alias("up-bytes-per-second")
                .visible_alias("up-speed")
                .value_parser(value_parser!(bytesize::ByteSize))
                .help("Bytes per second to upload. Typical suffixes are supported, eg, 5k. When specified, the packet interval is determined automatically from this and the upload packet length."),
            Arg::new("outgoing_finalize_delta")
                .long("outgoing-finalize-delta")
                .visible_alias("up-finalize-delta")
                .default_value(DEFAULT_FINALIZE_DELTA)
                .value_parser(humantime::parse_duration)
                .help("How long to finalize the contents of a packet to be sent before actually sending it. If too short, then packets may frequently be delayed and not sent at the intended times. This is most likely to happen under system load, and those delayed packets could indicate to an attacker that your system is under load. Warnings are logged whenever this happens, so increase this value if you see those warnings frequently."),
            Arg::new("incoming_packet_length")
                .long("incoming-packet-length")
                .visible_alias("down-packet-length")
                .value_parser(value_parser!(bytesize::ByteSize))
                .help("Fixed download packet length, in bytes"),
            Arg::new("incoming_packet_interval")
                .long("incoming-packet-interval")
                .visible_alias("down-packet-interval")
                .value_parser(humantime::parse_duration)
                .help("Fixed download packet interval, in nanoseconds"),
            Arg::new("incoming_bytes_per_second")
                .long("incoming-bytes-per-second")
                .visible_alias("incoming-speed")
                .visible_alias("down-bytes-per-second")
                .visible_alias("down-speed")
                .value_parser(value_parser!(bytesize::ByteSize))
                .help("Bytes per second to download. Typical suffixes are supported, eg, 5k. When specified, the packet interval is determined automatically from this and the download packet length."),
            Arg::new("incoming_finalize_delta")
                .long("incoming-finalize-delta")
                .visible_alias("down-finalize-delta")
                .default_value(DEFAULT_FINALIZE_DELTA)
                .value_parser(humantime::parse_duration)
                // TODO make sure we print warnings for delayed finalization on the server, on the
                // client (via statistics).
                .help("See --outgoing-finalize-delta docs"),
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
        let parse_interval = |in_or_out| -> WireInterval {
            match (
                matches.get_one::<Duration>(&format!("{in_or_out}_packet_interval")),
                matches.get_one::<bytesize::ByteSize>(&format!("{in_or_out}_bytes_per_second")),
            ) {
                (Some(interval), None) => WireInterval::Fixed(
                    interval
                        .as_nanos()
                        .try_into()
                        .expect("Don't put intervals longer than hundreds of years."),
                ),
                (None, Some(bytes_per_second)) => WireInterval::Rate(bytes_per_second.as_u64()),
                _ => unreachable!(
                    "Clap should enforce that either interval or bytes per second is set."
                ),
            }
        };
        WireConfiguration {
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
        }
    }
}

pub(crate) struct CommonConfiguration {
    pub(crate) pre_shared_key: Vec<u8>,
    pub(crate) listen_addr: String,
    pub(crate) tun_name: String,
    pub(crate) tun_mtu: Option<u16>,
    pub(crate) tun_ipv4: Option<String>,
    pub(crate) tun_ipv6: Option<String>,
}

impl EzClap for CommonConfiguration {
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
                .default_value(DEFAULT_LISTEN_ADDR)
                .help("Address and port to listen on."),
	    Arg::new("tun_name")
		.long("tun-name")
		.default_value(DEFAULT_TUN_NAME)
		.help("Name of the TUN device to use or create"),
            Arg::new("tun_mtu")
                .long("tun-mtu")
                .value_parser(value_parser!(u16))
                .help("MTU for the TUN device. It's okay for this to be larger than the packet length; I405 will fragment and reassemble packets as necessary. Defaults to the system default, usually 1500. I405 does not make any attempt to calculate the max TUN MTU such that the wrapped packets can also be sent out in one I405 packet; setting tun mtu to be substantially less than 1500 (eg, 1400) should be enough, and may improve latency a bit. However, because I405 tries to pack multiple wrapped packets into I405 packets, even a smaller MTU does not guarantee that sent packets will not be fragmented by I405."),
	    Arg::new("tun_ipv4")
		.long("tun-ipv4")
		.help("IPv4 address (optionally with netmask) to automatically assign and route to the TUN device."),
            Arg::new("tun_ipv6")
                .long("tun-ipv6")
                .help("IPv6 address (optionall with netmask) to automatically assign and route to the TUN device.")
        ]
    }

    fn from_match(matches: &ArgMatches) -> Self {
        CommonConfiguration {
            pre_shared_key: matches
                .get_one::<Vec<u8>>("pre_shared_key")
                .unwrap()
                .clone(),
            // TODO rename to bind_addr so it makes more sense on the client?
            listen_addr: matches.get_one::<String>("listen_addr").unwrap().clone(),
            tun_name: matches.get_one::<String>("tun_name").unwrap().clone(),
            tun_mtu: matches.get_one::<u16>("tun_mtu").cloned(),
            tun_ipv4: matches.get_one::<String>("tun_ipv4").cloned(),
            tun_ipv6: matches.get_one::<String>("tun_ipv6").cloned(),
        }
    }
}

pub(crate) struct ClientConfiguration {
    pub(crate) common_configuration: CommonConfiguration,
    pub(crate) wire_configuration: WireConfiguration,
    pub(crate) peer: String,
}

impl EzClap for ClientConfiguration {
    fn to_args() -> Vec<Arg> {
        let mut result = Vec::new();
        result.extend(CommonConfiguration::to_args());
        result.extend(WireConfiguration::to_args());
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
        result.extend(CommonConfiguration::to_groups());
        result.extend(WireConfiguration::to_groups());
        result
    }

    fn from_match(matches: &ArgMatches) -> Self {
        Self {
            common_configuration: CommonConfiguration::from_match(matches),
            wire_configuration: WireConfiguration::from_match(matches),
            peer: matches.get_one::<String>("peer").unwrap().clone(),
        }
    }
}

impl ContainsCommonConfiguration for ClientConfiguration {
    fn common_configuration(&self) -> &CommonConfiguration {
        &self.common_configuration
    }
}

pub(crate) struct ServerConfiguration {
    pub(crate) common_configuration: CommonConfiguration,
}

impl EzClap for ServerConfiguration {
    fn to_args() -> Vec<Arg> {
        CommonConfiguration::to_args()
    }

    fn to_groups() -> Vec<ArgGroup> {
        CommonConfiguration::to_groups()
    }

    fn from_match(matches: &ArgMatches) -> Self {
        Self {
            common_configuration: CommonConfiguration::from_match(matches),
        }
    }
}

impl ContainsCommonConfiguration for ServerConfiguration {
    fn common_configuration(&self) -> &CommonConfiguration {
        &self.common_configuration
    }
}

enum_dispatch! {
    pub(crate) trait ContainsCommonConfiguration {
        fn common_configuration(&self) -> &CommonConfiguration;
    }

    pub(crate) enum Configuration {
        Client(ClientConfiguration),
        Server(ServerConfiguration),
    }
}

fn client_command() -> Command {
    Command::new("client")
        .args(ClientConfiguration::to_args())
        .groups(ClientConfiguration::to_groups())
}

fn server_command() -> Command {
    Command::new("server")
        .args(ServerConfiguration::to_args())
        .groups(ServerConfiguration::to_groups())
}

fn main_command() -> Command {
    Command::new("I-405")
        .subcommand(client_command())
        .subcommand(server_command())
        .subcommand_required(true)
}

pub(crate) fn parse_args() -> Configuration {
    let top_level_matches = main_command().get_matches();
    match top_level_matches.subcommand() {
        Some(("client", matches)) => {
            Configuration::Client(ClientConfiguration::from_match(matches))
        }
        Some(("server", matches)) => {
            Configuration::Server(ServerConfiguration::from_match(matches))
        }
        _ => unreachable!(),
    }
}

// Aside: I think the Right Way to do options is have a struct which contains all the possible
// sources the option could have come from, and the value found in each spot (eg, CLI, config file,
// default value). Then there's a "get" method on each option, that tells you the effective value.
// This makes it much easier to merge configurations together, for example.
