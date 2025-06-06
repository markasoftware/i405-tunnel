use config::ContainsCommonConfiguration as _;
use wire_config::to_wire_configs;

mod array_array;
mod config;
mod constants;
mod core;
mod defragger;
mod dtls;
mod hardware;
mod logical_ip_packet;
mod messages;
mod queued_ip_packet;
mod utils;
mod wire_config;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let configuration = config::parse_args();
    let common_config = configuration.common_configuration();

    let mut hardware = hardware::real::RealHardware::new(
        common_config
            .listen_addr
            .parse()
            .expect("Failed to parse listen address"),
        common_config.tun_name.clone(),
        common_config.tun_mtu,
        common_config
            .tun_ipv4
            .as_ref()
            .map(|ipv4| ipv4.parse().expect("Failed to parse TUN IPv4 addr")),
        common_config
            .tun_ipv6
            .as_ref()
            .map(|ipv6| ipv6.parse().expect("Failed to parse TUN IPv6 addr")),
    )
    .expect("Failed to create tun and socket; are you root?");

    let mut core = match &configuration {
        config::Configuration::Client(client_configuration) => {
            // TODO do DNS resolving so we can use domains
            let peer: std::net::SocketAddr = client_configuration
                .peer
                .parse()
                .expect("Invalid peer syntax; use host:port");
            let wire_configs = to_wire_configs(&peer, &client_configuration.wire_configuration);
            let client_config = core::client::Config {
                c2s_wire_config: wire_configs.c2s,
                s2c_wire_config: wire_configs.s2c,
                peer_address: peer,
                pre_shared_key: common_config.pre_shared_key.clone(),
            };
            core::ConcreteCore::Client(
                core::client::Core::new(client_config, &mut hardware)
                    .expect("Failed to create client core"),
            )
        }
        config::Configuration::Server(_) => {
            let server_config = core::server::Config {
                pre_shared_key: common_config.pre_shared_key.clone(),
            };
            core::ConcreteCore::Server(
                core::server::Core::new(server_config, &mut hardware)
                    .expect("Failed to create server core"),
            )
        }
    };

    log::info!("Starting I405");
    hardware.run(&mut core);
}
