/// Utilities for creating "real" hardware that are used by both sleepy and spinny implementations.
use std::net::SocketAddr;

use anyhow::{Result, bail};

use crate::{config_cli::CommonConfigCli, constants::MAX_IP_PACKET_LENGTH};

/// Return the address that you can "connect" a UDP socket to to disconnect it, using the same IP
/// protocol version as listen_addr
pub(crate) fn disconnect_addr(listen_addr: SocketAddr) -> SocketAddr {
    match listen_addr {
        SocketAddr::V4(_) => SocketAddr::V4(std::net::SocketAddrV4::new(
            std::net::Ipv4Addr::from_bits(0),
            0,
        )),
        SocketAddr::V6(_) => SocketAddr::V6(std::net::SocketAddrV6::new(
            std::net::Ipv6Addr::from_bits(0),
            0,
            0,
            0,
        )),
    }
}

pub(crate) struct TunConfig {
    name: String,
    mtu: Option<u16>,
    ipv4_net: Option<ipnet::Ipv4Net>,
    ipv6_net: Option<ipnet::Ipv6Net>,
}

pub(crate) fn tun_config_from_common_config_cli(common_config_cli: &CommonConfigCli) -> TunConfig {
    TunConfig {
        name: common_config_cli.tun_name.clone(),
        mtu: common_config_cli.tun_mtu,
        ipv4_net: common_config_cli
            .tun_ipv4
            .as_ref()
            .map(|ipv4| ipv4.parse().expect("Failed to parse TUN IPv4 address")),
        ipv6_net: common_config_cli
            .tun_ipv6
            .as_ref()
            .map(|ipv6| ipv6.parse().expect("Failed to parse TUN IPv6 address")),
    }
}

/// Create tun, socket, and set scheduling policy.
pub(crate) fn make_tun(tun_config: TunConfig) -> Result<tun_rs::SyncDevice> {
    let mut tun_builder = tun_rs::DeviceBuilder::new().name(tun_config.name);
    let mtu = tun_config.mtu.unwrap_or(MAX_IP_PACKET_LENGTH.try_into().unwrap());
    if mtu > MAX_IP_PACKET_LENGTH.try_into().unwrap() {
        bail!("tun configured MTU {mtu} must not be greater than MAX_IP_PACKET_LENGTH = {MAX_IP_PACKET_LENGTH}");
    }
    tun_builder = tun_builder.mtu(mtu);
    if let Some(ipv4_net) = tun_config.ipv4_net {
        tun_builder = tun_builder.ipv4(ipv4_net.addr(), ipv4_net.netmask(), None);
    }
    if let Some(ipv6_net) = tun_config.ipv6_net {
        tun_builder = tun_builder.ipv6(ipv6_net.addr(), ipv6_net.netmask());
    }
    Ok(tun_builder.build_sync()?)
}

pub(crate) fn set_sched_fifo() -> Result<()> {
    let sched_param = libc::sched_param { sched_priority: 1 };
    // SAFETY: fuck that
    let setscheduler_ret = unsafe {
        libc::sched_setscheduler(
            0,
            libc::SCHED_FIFO,
            &sched_param as *const libc::sched_param,
        )
    };
    if setscheduler_ret == 0 {
        Ok(())
    } else {
        Err(anyhow::Error::from(std::io::Error::last_os_error())
            .context("Failed to set process scheduling mode to SCHED_FIFO; are you root?"))
    }
}
