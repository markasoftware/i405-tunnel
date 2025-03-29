mod config;
mod i405pp;
mod tcp;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    log::info!("Starting I405");

    let configuration = config::parse_args();

    match configuration {
        config::Configuration::TcpClient(top_level_tcp_client_configuration) => {
            tcp::client(top_level_tcp_client_configuration)
        }
        config::Configuration::TcpServer(top_level_tcp_server_configuration) => {
            tcp::server(top_level_tcp_server_configuration)
        }
    }

    // let args = CliArgs::parse();

    // println!("We would listen on port {:?}", args.transport_choice);
}
