use config::ContainsCommonConfiguration as _;

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

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let configuration = config::parse_args();
    let common_config = configuration.common_configuration();

    let mut hardware = hardware::real::RealHardware::new(
        common_config.listen_addr.parse().unwrap(),
        common_config.tun_name.clone(),
        common_config
            .tun_ipv4
            .as_ref()
            .map(|ipv4| ipv4.parse().unwrap()),
        common_config
            .tun_ipv6
            .as_ref()
            .map(|ipv6| ipv6.parse().unwrap()),
    )
    .unwrap();

    let mut core = match &configuration {
        config::Configuration::Client(client_configuration) => {
            let client_config = core::client::Config {
                c2s_wire_config: core::WireConfig {
                    packet_length: client_configuration
                        .wire_configuration
                        .outgoing_packet_length,
                    packet_interval: client_configuration
                        .wire_configuration
                        .outgoing_packet_interval,
                    // TODO not 0
                    packet_interval_offset: 0,
                },
                s2c_wire_config: core::WireConfig {
                    packet_length: client_configuration
                        .wire_configuration
                        .incoming_packet_length,
                    packet_interval: client_configuration
                        .wire_configuration
                        .incoming_packet_interval,
                    // TODO not 0
                    packet_interval_offset: 0,
                },
                // TODO do DNS resolving so we can use domains
                peer_address: client_configuration.peer.parse().unwrap(),
                pre_shared_key: common_config.pre_shared_key.clone(),
            };
            core::ConcreteCore::Client(
                core::client::Core::new(client_config, &mut hardware).unwrap(),
            )
        }
        config::Configuration::Server(_) => {
            let server_config = core::server::Config {
                pre_shared_key: common_config.pre_shared_key.clone(),
            };
            core::ConcreteCore::Server(
                core::server::Core::new(server_config, &mut hardware).unwrap(),
            )
        }
    };

    log::info!("Starting I405");
    hardware.run(&mut core);
}
