use std::path::PathBuf;

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

pub struct TlsClientConfiguration {
    pub certificate_authority_path: PathBuf,
}

impl EzClap for TlsClientConfiguration {
    fn to_args() -> Vec<Arg> {
        vec![
            Arg::new("certificate_authority_path")
                .long("certificate-authority-path")
                .visible_alias("ca-path")
                .value_parser(value_parser!(PathBuf))
                .required(true)
                .help("Path to the certificate authority file"),
        ]
    }

    fn from_match(matches: &ArgMatches) -> Self {
        TlsClientConfiguration {
            certificate_authority_path: matches
                .get_one::<PathBuf>("certificate_authority_path")
                .unwrap()
                .clone(),
        }
    }
}

pub struct TlsServerConfiguration {
    pub certificate_path: PathBuf,
}

impl EzClap for TlsServerConfiguration {
    fn to_args() -> Vec<Arg> {
        vec![
            Arg::new("certificate_path")
                .long("certificate-path")
                .visible_alias("cert-path")
                .value_parser(value_parser!(PathBuf))
                .required(true)
                .help("Path to the certificate file"),
        ]
    }

    fn from_match(matches: &ArgMatches) -> Self {
        TlsServerConfiguration {
            certificate_path: matches
                .get_one::<PathBuf>("certificate_path")
                .unwrap()
                .clone(),
        }
    }
}

pub struct TcpClientConfiguration {
    pub socks_listen_port: u16,
    pub i405_server_host: String,
    pub i405_server_port: u16,
}

impl EzClap for TcpClientConfiguration {
    fn to_args() -> Vec<Arg> {
        vec![
            Arg::new("socks_listen_port")
                .long("socks-listen-port")
                .visible_alias("socks-port")
                .value_parser(value_parser!(u16))
                .default_value("1080")
                .help("Port to listen on for SOCKS connections"),
            Arg::new("i405_server_host")
                .long("i405-server-host")
                .visible_alias("i405-host")
                .required(true)
                .help("I405 server to connect to."),
            Arg::new("i405_server_port")
                .long("i405-server-port")
                .visible_alias("i405-port")
                .value_parser(value_parser!(u16))
                .default_value(DEFAULT_I405_PORT_STR)
                .help("I405 server port to connect to"),
        ]
    }

    fn from_match(matches: &ArgMatches) -> Self {
        TcpClientConfiguration {
            socks_listen_port: matches.get_one::<u16>("socks_listen_port").unwrap().clone(),
            i405_server_host: matches
                .get_one::<String>("i405_server_host")
                .unwrap()
                .clone(),
            i405_server_port: matches.get_one::<u16>("i405_server_port").unwrap().clone(),
        }
    }
}

pub struct TcpServerConfiguration {
    pub i405_listen_host: String,
    pub i405_listen_port: u16,
}

impl EzClap for TcpServerConfiguration {
    fn to_args() -> Vec<Arg> {
        vec![
            // TODO allow multiple listen hosts.
            Arg::new("i405_listen_host")
                .long("i405-listen-host")
                .visible_alias("i405-host")
                .default_value("0.0.0.0")
                .help("Host to listen on."),
            Arg::new("i405_listen_port")
                .long("i405-listen-port")
                .visible_alias("i405-port")
                .value_parser(value_parser!(u16))
                .default_value(DEFAULT_I405_PORT_STR)
                .help("I405 server port to listen on."),
        ]
    }

    fn from_match(matches: &ArgMatches) -> Self {
        TcpServerConfiguration {
            i405_listen_host: matches
                .get_one::<String>("i405_listen_host")
                .unwrap()
                .clone(),
            i405_listen_port: matches.get_one::<u16>("i405_listen_port").unwrap().clone(),
        }
    }
}

pub struct TunConfiguration {
    pub tun_name: String,
    pub tun_ip: Option<String>,
}

impl EzClap for TunConfiguration {
    fn to_args() -> Vec<Arg> {
        vec![
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
        TunConfiguration {
            tun_name: matches.get_one::<String>("tun_name").unwrap().clone(),
            tun_ip: matches.get_one::<String>("tun_ip").cloned(),
        }
    }
}

pub struct CommonConfiguration {}

impl EzClap for CommonConfiguration {
    fn to_args() -> Vec<Arg> {
        vec![]
    }

    fn from_match(_matches: &ArgMatches) -> Self {
        CommonConfiguration {}
    }
}

pub struct TopLevelTcpClientConfiguration {
    common_configuration: CommonConfiguration,
    wire_configuration: WireConfiguration,
    tls_client_configuration: TlsClientConfiguration,
    tcp_client_configuration: TcpClientConfiguration,
}

pub struct TopLevelTcpServerConfiguration {
    common_configuration: CommonConfiguration,
    tls_server_configuration: TlsServerConfiguration,
    tcp_server_configuration: TcpServerConfiguration,
}

pub struct TopLevelTunClientConfiguration {
    common_configuration: CommonConfiguration,
    wire_configuration: WireConfiguration,
    tls_client_configuration: TlsClientConfiguration,
    tun_configuration: TunConfiguration,
}

pub struct TopLevelTunServerConfiguration {
    common_configuration: CommonConfiguration,
    tls_server_configuration: TlsServerConfiguration,
    tun_configuration: TunConfiguration,
}

pub enum Configuration {
    TcpClient(TopLevelTcpClientConfiguration),
    TcpServer(TopLevelTcpServerConfiguration),
    // TunClient(TopLevelTunClientConfiguration),
    // TunServer(TopLevelTunServerConfiguration),
}

fn tcp_client_command() -> Command {
    Command::new("tcp-client")
        .args(CommonConfiguration::to_args())
        .args(WireConfiguration::to_args())
        .args(TlsClientConfiguration::to_args())
        .args(TcpClientConfiguration::to_args())
}

fn tcp_server_command() -> Command {
    Command::new("tcp-server")
        .args(CommonConfiguration::to_args())
        .args(TlsServerConfiguration::to_args())
        .args(TcpServerConfiguration::to_args())
}

fn main_command() -> Command {
    Command::new("I-405")
        .subcommand(tcp_client_command())
        .subcommand(tcp_server_command())
}

pub fn parse_args() -> Configuration {
    let top_level_matches = main_command().get_matches();
    match top_level_matches.subcommand() {
        Some(("tcp-client", matches)) => Configuration::TcpClient(TopLevelTcpClientConfiguration {
            common_configuration: CommonConfiguration::from_match(matches),
            wire_configuration: WireConfiguration::from_match(matches),
            tls_client_configuration: TlsClientConfiguration::from_match(matches),
            tcp_client_configuration: TcpClientConfiguration::from_match(matches),
        }),
        Some(("tcp-server", matches)) => Configuration::TcpServer(TopLevelTcpServerConfiguration {
            common_configuration: CommonConfiguration::from_match(matches),
            tls_server_configuration: TlsServerConfiguration::from_match(matches),
            tcp_server_configuration: TcpServerConfiguration::from_match(matches),
        }),
        _ => unreachable!(),
    }
}

// Aside: I think the Right Way to do options is have a struct which contains all the possible
// sources the option could have come from, and the value found in each spot (eg, CLI, config file,
// default value). Then there's a "get" method on each option, that tells you the effective value.
// This makes it much easier to merge configurations together, for example.
