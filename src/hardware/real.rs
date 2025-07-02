/// Utilities for creating "real" hardware that are used by both sleepy and spinny implementations.
use std::{net::SocketAddr, time::Duration};

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

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct QdiscSettings {
    target: Duration,
    interval: Duration,
    limit: u64,
    quantum: u64,
}

impl QdiscSettings {
    pub(crate) fn new(
        outgoing_interval_max: Duration,
        incoming_interval_max: Duration,
    ) -> QdiscSettings {
        let target = outgoing_interval_max * 3 / 2 + Duration::from_millis(5);
        QdiscSettings {
            // most of these numbers derived from
            // https://www.bufferbloat.net/projects/codel/wiki/Best_practices_for_benchmarking_Codel_and_FQ_Codel/
            // as per link above, we want the interval to be above the packet interval. Adding 5ms
            // is just an easy way to make sure it doesn't get super short at higher bandwidths
            target,
            // recommended for this to be worst-case RTT -- we should probably make this
            // user-configurable, but until then, take 200ms as an RTT estimate and then add
            // worst-case intervals in both directions.
            interval: std::cmp::max(
                target * 2,
                outgoing_interval_max + incoming_interval_max + Duration::from_millis(200),
            ),
            // haven't tested this, but the link above recommends it for 10mbit. It still seems
            // questionably estimate 1 second worth. This is fairly close to the recommendation of
            // 600 for 10mbit from the link above.
            limit: std::cmp::max(
                20,
                Duration::from_secs(1).div_duration_f64(outgoing_interval_max) as u64,
            ),
            // general recommendation from that link for lower bandwidths
            quantum: 300,
        }
    }
}

pub(crate) fn configure_qdisc(interface_name: &str, settings: &QdiscSettings) {
    log::debug!(
        "Configuring fq_codel target {}us interval {}us limit {} quantum {}",
        settings.target.as_micros(),
        settings.interval.as_micros(),
        settings.limit,
        settings.quantum
    );

    // How hard is it to do this with syscalls? It seems to involve `sendmsg` with lots of special
    // flags. Just setting the qdisc doesn't seem to bad, but specifying the options looks a little
    // more involved, so let's just use `tc`.

    // TODO we may not want to panic when these commands fail, in case there's some way that
    // interval settings can cause the `tc` command to crash but we don't want the program to crash.
    let exit_code = std::process::Command::new("tc")
        .arg("qdisc")
        .arg("replace")
        .arg("dev")
        .arg(interface_name)
        .arg("root")
        .arg("fq_codel")
        .arg("target")
        .arg(format!("{}us", settings.target.as_micros()))
        .arg("interval")
        .arg(format!("{}us", settings.interval.as_micros()))
        .arg("limit")
        .arg(format!("{}", settings.limit))
        .arg("quantum")
        .arg(format!("{}", settings.quantum))
        .status()
        .expect("Error running `tc` command to configure qdisc:");
    if !exit_code.success() {
        panic!("Nonzero exit code configuring qdisc: {exit_code}");
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn qdisc_settings() {
        let settings = QdiscSettings::new(Duration::from_millis(10), Duration::from_millis(25));
        assert_eq!(
            settings,
            QdiscSettings {
                target: Duration::from_millis(20),
                interval: Duration::from_millis(235),
                limit: 100,
                quantum: 300,
            }
        )
    }
}
