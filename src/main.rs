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
    log::info!("Starting I405");

    let configuration = config::parse_args();
}
