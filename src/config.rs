use clap::{Arg, ArgMatches, Command, value_parser};
use declarative_enum_dispatch::enum_dispatch;

const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:1405";
const DEFAULT_TUN_NAME: &str = "tun-i405";

trait EzClap {
    fn to_args() -> Vec<Arg>;
    fn from_match(matches: &ArgMatches) -> Self;
}

pub(crate) struct WireConfiguration {
    pub(crate) outgoing_packet_length: u16,
    pub(crate) outgoing_packet_interval: u64,
    pub(crate) incoming_packet_length: u16,
    pub(crate) incoming_packet_interval: u64,
}

impl EzClap for WireConfiguration {
    fn to_args() -> Vec<Arg> {
        vec![
            Arg::new("outgoing_packet_length")
                .long("outgoing-packet-length")
                .visible_alias("upload-packet-length")
                .value_parser(value_parser!(u16))
                .required(true)
                .help("Fixed upload packet length, in bytes"),
            Arg::new("outgoing_packet_interval")
                .long("outgoing-packet-interval")
                .visible_alias("upload-packet-interval")
                .value_parser(value_parser!(u64))
                .required(true)
                .help("Fixed upload packet interval, in nanoseconds"),
            Arg::new("incoming_packet_length")
                .long("incoming-packet-length")
                .visible_alias("download-packet-length")
                .value_parser(value_parser!(u16))
                .required(true)
                .help("Fixed download packet length, in bytes"),
            Arg::new("incoming_packet_interval")
                .long("incoming-packet-interval")
                .visible_alias("download-packet-interval")
                .value_parser(value_parser!(u64))
                .required(true)
                .help("Fixed download packet interval, in nanoseconds"),
        ]
    }

    fn from_match(matches: &ArgMatches) -> Self {
        WireConfiguration {
            outgoing_packet_length: matches
                .get_one::<u16>("outgoing_packet_length")
                .unwrap()
                .clone(),
            outgoing_packet_interval: matches
                .get_one::<u64>("outgoing_packet_interval")
                .unwrap()
                .clone(),
            incoming_packet_length: matches
                .get_one::<u16>("incoming_packet_length")
                .unwrap()
                .clone(),
            incoming_packet_interval: matches
                .get_one::<u64>("incoming_packet_interval")
                .unwrap()
                .clone(),
        }
    }
}

pub(crate) struct CommonConfiguration {
    pub(crate) pre_shared_key: Vec<u8>,
    pub(crate) listen_addr: String,
    pub(crate) tun_name: String,
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
            listen_addr: matches.get_one::<String>("listen_addr").unwrap().clone(),
            tun_name: matches.get_one::<String>("tun_name").unwrap().clone(),
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
    Command::new("client").args(ClientConfiguration::to_args())
}

fn server_command() -> Command {
    Command::new("server").args(ServerConfiguration::to_args())
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
