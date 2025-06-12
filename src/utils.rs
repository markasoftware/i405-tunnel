use std::{net::SocketAddr, time::Duration};

use crate::constants::{IPV4_HEADER_LENGTH, IPV6_HEADER_LENGTH, UDP_HEADER_LENGTH};

pub(crate) fn ns_to_str(ns: u64) -> String {
    humantime::format_duration(Duration::from_nanos(ns)).to_string()
}

pub(crate) fn ip_mtu_to_udp_mtu(ip_mtu: u16, peer: SocketAddr) -> u16 {
    match peer {
        SocketAddr::V4(_) => ip_mtu.checked_sub(IPV4_HEADER_LENGTH).unwrap(),
        SocketAddr::V6(_) => ip_mtu.checked_sub(IPV6_HEADER_LENGTH).unwrap(),
    }
}

pub(crate) fn ip_mtu_to_dtls_mtu(ip_mtu: u16, peer: SocketAddr) -> u16 {
    ip_mtu_to_udp_mtu(ip_mtu, peer)
        .checked_sub(UDP_HEADER_LENGTH)
        .unwrap()
}
