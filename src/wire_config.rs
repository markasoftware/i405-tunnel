use std::net::SocketAddr;

use crate::config::{WireConfiguration, WireInterval};
use crate::constants::{
    DTLS_HEADER_LENGTH, IPV4_HEADER_LENGTH, IPV6_HEADER_LENGTH, UDP_HEADER_LENGTH,
};
use crate::utils::ns_to_str;

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct WireConfig {
    pub(crate) packet_length: u16,
    pub(crate) packet_interval: u64,
    // packets will be sent when (epoch_time - packet_interval_offset) % packet_interval == 0
    pub(crate) packet_interval_offset: u64,
    // How long to send the packet to the sending thread before the actual scheduled send time.
    pub(crate) packet_finalize_delta: u64,
}

pub(crate) struct WireConfigs {
    pub(crate) c2s: WireConfig,
    pub(crate) s2c: WireConfig,
}

fn to_wire_config(
    c2s_or_s2c: &str,
    interface_name: &str,
    mtu: u16,
    max_packet_length: u16,
    packet_length: Option<u64>,
    interval: &WireInterval,
    finalize_delta: u64,
) -> WireConfig {
    let packet_length: u16 = packet_length
        .map(|pl| {
            pl.try_into()
                .expect(&format!("Packet length {pl} is too long; must be <={}", u16::MAX))
        })
        .unwrap_or_else(|| {
            log::info!(
                "Using default packet length {max_packet_length} derived from MTU {mtu} of interface {interface_name} in place of omitted {c2s_or_s2c} packet length"
            );
            max_packet_length
        });
    if packet_length > max_packet_length {
        log::warn!(
            "Specified {c2s_or_s2c} packet length {packet_length} bytes is greater than automatic maximum based on MTU of {max_packet_length} bytes, so IP fragmentation may occur -- please reconsider"
        );
    }
    let packet_interval: u64 = match interval {
        // TODO print the computed speed from the interval. Or maybe, just print the whole goddamn
        // config for both directions as well as the speed, since we always need to print something.
        WireInterval::Fixed(fixed_interval) => *fixed_interval,
        WireInterval::Rate(bytes_per_second) => {
            let interval = u64::from(packet_length)
                .checked_mul(1_000_000_000)
                .unwrap()
                .checked_div(*bytes_per_second)
                .unwrap();
            log::info!(
                "Using {c2s_or_s2c} computed packet interval of {}",
                ns_to_str(interval)
            );
            interval
        }
    };
    // TODO if the packet_interval is long, and packet length was not explicitly set, we should
    // automaticaly set it to a shorter value to decrease latency.
    WireConfig {
        packet_length,
        packet_interval,
        // TODO randomize:
        packet_interval_offset: 0,
        packet_finalize_delta: finalize_delta,
    }
}

pub(crate) fn to_wire_configs(
    peer: &SocketAddr,
    wire_configuration: &WireConfiguration,
) -> WireConfigs {
    let (interface_name, mtu_usize) =
        mtu::interface_and_mtu(peer.ip()).expect("Error computing interface MTU");
    let mtu = mtu_usize.try_into().unwrap_or(u16::MAX);
    let ip_packet_header_length = match peer {
        SocketAddr::V4(_) => IPV4_HEADER_LENGTH,
        SocketAddr::V6(_) => IPV6_HEADER_LENGTH,
    };
    let all_headers_length = ip_packet_header_length
        .checked_add(UDP_HEADER_LENGTH)
        .unwrap()
        .checked_add(DTLS_HEADER_LENGTH)
        .unwrap();
    let max_packet_length = mtu.checked_sub(all_headers_length).expect(&format!("Interface {interface_name} has an MTU of {mtu}, which is too short to fit a useful I405 packet"));

    if wire_configuration.outgoing_packet_length.is_none()
        || wire_configuration.incoming_packet_length.is_none()
    {}

    WireConfigs {
        c2s: to_wire_config(
            "client-to-server",
            &interface_name,
            mtu,
            max_packet_length,
            wire_configuration.outgoing_packet_length,
            &wire_configuration.outgoing_interval,
            wire_configuration.outgoing_finalize_delta,
        ),
        s2c: to_wire_config(
            "server-to-client",
            &interface_name,
            mtu,
            max_packet_length,
            wire_configuration.incoming_packet_length,
            &wire_configuration.incoming_interval,
            wire_configuration.incoming_finalize_delta,
        ),
    }
}
