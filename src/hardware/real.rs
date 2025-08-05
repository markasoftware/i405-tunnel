/// Utilities for creating "real" hardware that are used by both sleepy and spinny implementations.
use std::{
    net::{SocketAddr, ToSocketAddrs},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Result, anyhow, bail};

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

pub(crate) fn epoch_timestamp() -> u64 {
    (SystemTime::now().duration_since(UNIX_EPOCH))
        .unwrap()
        .as_nanos()
        .try_into()
        .unwrap()
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
    let mtu = tun_config
        .mtu
        .unwrap_or(MAX_IP_PACKET_LENGTH.try_into().unwrap());
    if mtu > MAX_IP_PACKET_LENGTH.try_into().unwrap() {
        bail!(
            "tun configured MTU {mtu} must not be greater than MAX_IP_PACKET_LENGTH = {MAX_IP_PACKET_LENGTH}"
        );
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

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) struct QdiscSettings {
    fq_flow_limit: u64,
    fq_quantum: u64,
    tun_hardware_queue_len: u32,
}

impl QdiscSettings {
    pub(crate) fn new(outgoing_interval_max: Duration) -> QdiscSettings {
        QdiscSettings {
            // 500ms max per-flow buffering. Complete empirical crap
            fq_flow_limit: std::cmp::max(
                20,
                Duration::from_millis(500).div_duration_f64(outgoing_interval_max) as u64,
            ),
            // this is kinda recommended for slow flows in fq_codel. I'm not sure what setting this
            // to less than the MTU really does (some bufferbloat wiki pages suggest that it "favors
            // small packets", which sounds nice), but I definitely see the wisdom in decreasing it
            // from the default of 2*MTU -- no reason to let the same flow send more than one packet
            // before switching at low speeds
            fq_quantum: 300,
            // 50ms worth of "hardware" buffering -- this is empirical and honestly complete crap --
            // need to revisit TODO
            tun_hardware_queue_len: std::cmp::max(
                3,
                Duration::from_millis(50)
                    .div_duration_f64(outgoing_interval_max)
                    .ceil() as u32,
            ),
        }
    }
}

pub(crate) fn configure_qdisc(
    interface_name: &str,
    tun: &tun_rs::SyncDevice,
    settings: &QdiscSettings,
) -> Result<()> {
    log::debug!("Configuring qdisc -- {:?}", settings);

    // TODO return a Result instead
    tun.set_tx_queue_len(settings.tun_hardware_queue_len)
        .map_err(|err| anyhow!(err).context("Setting TUN tq queue length"))?;

    // How hard is it to do this with syscalls? It seems to involve `sendmsg` with lots of special
    // flags. Just setting the qdisc doesn't seem to bad, but specifying the options looks a little
    // more involved, so let's just use `tc`.

    // TODO we may not want to panic when these commands fail, in case there's some way that
    // interval settings can cause the `tc` command to crash but we don't want the program to crash.
    // TODO consider going back to fq_codel to keep TCP sockets rtts lower. fq_codel has the slight
    // disadvantage that, because it drops packets at the head of the queue instead of the tail, it
    // actually drops packets, rather than effectively backpressuring the TCP stack without dropping
    // packets.
    let exit_code = std::process::Command::new("tc")
        .arg("qdisc")
        .arg("replace")
        .arg("dev")
        .arg(interface_name)
        .arg("root")
        .arg("fq")
        .arg("flow_limit")
        .arg(format!("{}", settings.fq_flow_limit))
        .arg("quantum")
        .arg(format!("{}", settings.fq_quantum))
        .status()
        .map_err(|err| anyhow!(err).context("Calling `tc` to configure qdisc"))?;
    if !exit_code.success() {
        bail!("Nonzero exit code when using `tc` to configure qdisc: {exit_code}");
    }

    Ok(())
}

pub(crate) fn resolve_socket_addr_string(socket_addr_str: &str) -> Option<SocketAddr> {
    let addrs: Vec<SocketAddr> = socket_addr_str
        .to_socket_addrs()
        .unwrap_or_else(|_| {
            panic!(
                "Failed to resolve peer address {}. Make sure to include a port number",
                socket_addr_str
            )
        })
        .collect();
    // prefer IPv6, but fall back to IPv4
    let ipv6_addr = addrs.iter().find(|addr| {
        // a bit hacky, but the easiest way to check routability is to just find the MTU,
        // since that involves a route table lookup and we already require the MTU library.
        addr.is_ipv6() && mtu::interface_and_mtu(addr.ip()).is_ok()
    });
    let ipv4_addr = addrs
        .iter()
        .find(|addr| addr.is_ipv4() && mtu::interface_and_mtu(addr.ip()).is_ok());
    ipv6_addr.or(ipv4_addr).cloned()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn qdisc_settings() {
        let settings = QdiscSettings::new(Duration::from_millis(10));
        assert_eq!(
            settings,
            QdiscSettings {
                fq_flow_limit: 50,
                fq_quantum: 300,
                tun_hardware_queue_len: 5,
            }
        )
    }
}
