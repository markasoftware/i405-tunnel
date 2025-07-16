use config_cli::ContainsCommonConfigCli as _;
use hardware::{
    Hardware,
    real::{resolve_socket_addr_string, set_sched_fifo},
};
use wire_config::to_wire_configs;

mod array_array;
mod config_cli;
mod constants;
mod core;
mod defragger;
mod deviation_stats;
mod dtls;
mod hardware;
mod jitter;
mod messages;
mod queued_ip_packet;
mod utils;
mod wire_config;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let configuration = config_cli::parse_args();
    let common_config_cli = configuration.common_config_cli();

    let tun_config = hardware::real::tun_config_from_common_config_cli(common_config_cli);
    let tun = hardware::real::make_tun(tun_config).expect("Failed to construct TUN; are you root?");
    let default_listen_addr = match configuration {
        config_cli::ConfigCli::Client(_) => "0.0.0.0:0",
        config_cli::ConfigCli::Server(_) => "0.0.0.0:1405",
    };
    let listen_addr = common_config_cli
        .listen_addr
        .clone()
        .unwrap_or(default_listen_addr.to_string())
        .parse()
        .expect("Failed to parse listen address as IP:PORT");

    match common_config_cli.poll_mode {
        config_cli::PollMode::Sleepy => {
            let sched_fifo = !common_config_cli.no_sched_fifo;
            if sched_fifo {
                // TODO warn if there's only one core, this could get real bad
                set_sched_fifo().expect("Failed to set SCHED_FIFO");
            }

            let hardware = hardware::sleepy::SleepyHardware::new(
                listen_addr,
                tun,
                common_config_cli.outgoing_send_deviation_stats,
            )
            .expect("Failed to construct SleepyHardware");
            let core = make_core(&configuration, &hardware);
            log::info!("Starting I405 (sleepy)");
            hardware.run(core);
        }
        config_cli::PollMode::Spinny => {
            let sched_fifo = !common_config_cli.no_sched_fifo;
            if sched_fifo {
                set_sched_fifo().expect("Failed to set SCHED_FIFO");
            }

            let hardware = hardware::spinny::SpinnyHardware::new(
                listen_addr,
                tun,
                common_config_cli.outgoing_send_deviation_stats,
            )
            .expect("Failed to construct SpinnyHardware");
            let core = make_core(&configuration, &hardware);
            log::info!("Starting I405 (spinny)");
            hardware.run(core);
        }
    };
}

fn make_core(
    configuration: &config_cli::ConfigCli,
    hardware: &impl Hardware,
) -> core::ConcreteCore {
    let common_config_cli = configuration.common_config_cli();

    match &configuration {
        config_cli::ConfigCli::Client(client_configuration) => {
            let peer = resolve_socket_addr_string(&client_configuration.peer).expect(&format!(
                "No route to host {} (but DNS resolved successfully); check your internet connectivity",
                client_configuration.peer
            ));
            let wire_configs = to_wire_configs(&peer, &client_configuration.wire_configuration);
            let client_config = core::client::Config {
                client_wire_config: wire_configs.client,
                server_wire_config: wire_configs.server,
                peer_address: peer,
                pre_shared_key: common_config_cli.pre_shared_key.clone(),
                should_configure_qdisc: !common_config_cli.no_tun_qdisc,
            };
            core::ConcreteCore::Client(
                core::client::Core::new(client_config, hardware)
                    .expect("Failed to create client core"),
            )
        }
        config_cli::ConfigCli::Server(_) => {
            let server_config = core::server::Config {
                pre_shared_key: common_config_cli.pre_shared_key.clone(),
                should_configure_qdisc: !common_config_cli.no_tun_qdisc,
            };
            core::ConcreteCore::Server(
                core::server::Core::new(server_config, hardware)
                    .expect("Failed to create server core"),
            )
        }
    }
}
