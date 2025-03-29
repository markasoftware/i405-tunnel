use crate::config;

pub fn client(config: config::TopLevelTcpClientConfiguration) {
    log::info!("Starting as client");
}

pub fn server(config: config::TopLevelTcpServerConfiguration) {
    log::info!("Starting as server");
}
