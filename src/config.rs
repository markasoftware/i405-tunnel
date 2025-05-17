use clap::{Arg, ArgMatches, Command, value_parser};

const DEFAULT_I405_PORT_STR: &str = "1405";
const DEFAULT_TUN_NAME: &str = "tun-i405";

trait EzClap {
    fn to_args() -> Vec<Arg>;
    fn from_match(matches: &ArgMatches) -> Self;
}

pub struct WireConfiguration {
    pub up_speed_bytes_per_second: u64,
    pub down_speed_bytes_per_second: u64,
    pub packet_size_bytes: Option<u32>,
}

impl EzClap for WireConfiguration {
    fn to_args() -> Vec<Arg> {
        vec![
	    Arg::new("up_speed_bytes_per_second")
		.long("up-speed-bytes-per-second")
		.visible_alias("up-speed")
		.value_parser(value_parser!(u64))
		.required(true)
		.help("Fixed upload speed, in bytes/second"),
	    Arg::new("down_speed_bytes_per_second")
		.long("down-speed-bytes-per-second")
		.visible_alias("down-speed")
		.value_parser(value_parser!(u64))
		.required(true)
		.help("Fixed download speed, in bytes/second"),
	    Arg::new("packet_size_bytes")
		.long("packet-size-bytes")
		.visible_alias("packet-size")
		.value_parser(value_parser!(u64))
		.help(
		    "Fixed packet size. In TCP mode, we do not have direct control over the packet size, so this option simply controls the size of the buffer handed to `write` at regular intervals. the kernel controls when packets are actually sent out, but should send packets immediately when possible. The kernel may send longer or shorter packets as it sees fit. In TUN mode, packets will be exactly the specified size."
		),
	]
    }

    fn from_match(matches: &ArgMatches) -> Self {
        WireConfiguration {
            up_speed_bytes_per_second: matches
                .get_one::<u64>("up_speed_bytes_per_second")
                .unwrap()
                .clone(),
            down_speed_bytes_per_second: matches
                .get_one::<u64>("down_speed_bytes_per_second")
                .unwrap()
                .clone(),
            packet_size_bytes: matches.get_one::<u32>("packet_size_bytes").cloned(),
        }
    }
}

pub struct CommonConfiguration {
    pub pre_shared_key: Vec<u8>,
    pub tun_name: String,
    pub tun_ip: Option<String>,
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
	    Arg::new("tun_name")
		.long("tun-name")
		.default_value(DEFAULT_TUN_NAME)
		.help("Name of the TUN device to use or create"),
	    Arg::new("tun_ip")
		.long("tun-ip")
		.help("IP address (optionally with netmask) to assign to the TUN device. Omit if you'll handle it yourself."),
        ]
    }

    fn from_match(matches: &ArgMatches) -> Self {
        CommonConfiguration {
            pre_shared_key: matches
                .get_one::<Vec<u8>>("pre_shared_key")
                .unwrap()
                .clone(),
            tun_name: matches.get_one::<String>("tun_name").unwrap().clone(),
            tun_ip: matches.get_one::<String>("tun_ip").cloned(),
        }
    }
}

pub struct ClientConfiguration {
    common_configuration: CommonConfiguration,
    wire_configuration: WireConfiguration,
}

pub struct ServerConfiguration {
    common_configuration: CommonConfiguration,
}

pub enum Configuration {
    Client(ClientConfiguration),
    Server(ServerConfiguration),
}

fn client_command() -> Command {
    Command::new("client")
        .args(CommonConfiguration::to_args())
        .args(WireConfiguration::to_args())
}

fn server_command() -> Command {
    Command::new("server")
        .args(CommonConfiguration::to_args())
}

fn main_command() -> Command {
    Command::new("I-405")
        .subcommand(client_command())
        .subcommand(server_command())
}

pub fn parse_args() -> Configuration {
    let top_level_matches = main_command().get_matches();
    match top_level_matches.subcommand() {
        Some(("client", matches)) => Configuration::Client(ClientConfiguration {
            common_configuration: CommonConfiguration::from_match(matches),
            wire_configuration: WireConfiguration::from_match(matches),
        }),
        Some(("server", matches)) => Configuration::Server(ServerConfiguration {
            common_configuration: CommonConfiguration::from_match(matches),
        }),
        _ => unreachable!(),
    }
}

// Aside: I think the Right Way to do options is have a struct which contains all the possible
// sources the option could have come from, and the value found in each spot (eg, CLI, config file,
// default value). Then there's a "get" method on each option, that tells you the effective value.
// This makes it much easier to merge configurations together, for example.
