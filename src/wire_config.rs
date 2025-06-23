use std::net::SocketAddr;

use crate::config_cli::{AverageWireIntervalCli, WireConfigCli, WireIntervalCli};
use crate::constants::{
    DTLS_HEADER_LENGTH, IPV4_HEADER_LENGTH, IPV6_HEADER_LENGTH, UDP_HEADER_LENGTH,
};
use crate::jitter::Jitterator;
use crate::utils::ns_to_str;

/// What fraction of the interval's average length should be the jitter, when the user doesn't
/// explicitly specify jitter?
const DEFAULT_JITTER_FRACTION: f64 = 0.25;
/// Do not allow the interval length lower bound to be less than this.
const MIN_MIN_INTERVAL: u64 = 50_000;

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct WireConfig {
    pub(crate) packet_length: u16,
    // interval will be in [min, max]
    pub(crate) packet_interval_min: u64,
    pub(crate) packet_interval_max: u64,
    // How long to send the packet to the sending thread before the actual scheduled send time.
    pub(crate) packet_finalize_delta: u64,
}

pub(crate) struct WireConfigs {
    pub(crate) c2s: WireConfig,
    pub(crate) s2c: WireConfig,
}

impl WireConfig {
    /// Always constructs a new jitterator, no singleton logic
    pub(crate) fn jitterator(&self) -> Jitterator {
        Jitterator::new(self.packet_interval_min, self.packet_interval_max)
    }
}

fn to_wire_config(
    c2s_or_s2c: &str,
    interface_name: &str,
    mtu: u16,
    max_packet_length: u16,
    packet_length: Option<u64>,
    interval: &WireIntervalCli,
    packet_finalize_delta: u64,
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
    let average_interval: u64 = match interval.average_interval {
        // TODO print the computed speed from the interval. Or maybe, just print the whole goddamn
        // config for both directions as well as the speed, since we always need to print something.
        AverageWireIntervalCli::Fixed(fixed_interval) => fixed_interval,
        AverageWireIntervalCli::Rate(bytes_per_second) => u64::from(packet_length)
            .checked_mul(1_000_000_000)
            .unwrap()
            .checked_div(bytes_per_second)
            .unwrap(),
    };
    let (packet_interval_min, packet_interval_max) = match interval.jitter {
        Some(jitter) => (
            average_interval.checked_sub(jitter).expect(&format!(
                "Specified jitter of {} is larger than the average inter-packet interval {}",
                ns_to_str(jitter),
                ns_to_str(average_interval)
            )),
            average_interval + jitter,
        ),
        None => {
            let max_jitter = (average_interval as f64 * DEFAULT_JITTER_FRACTION).floor() as u64;
            (average_interval - max_jitter, average_interval + max_jitter)
        }
    };
    log::info!(
        "Computed packet intervals (w/ jitter) will be between {} and {}",
        ns_to_str(packet_interval_min),
        ns_to_str(packet_interval_max)
    );
    assert!(
        packet_interval_min >= MIN_MIN_INTERVAL,
        "Min packet interval {} is too small must be at least {}. I405 won't be able to consistently dispatch packets at the right time, which can compromise privacy. Try setting a lower bandwidth / higher inter-packet interval.",
        ns_to_str(packet_interval_min),
        ns_to_str(MIN_MIN_INTERVAL),
    );
    assert!(
        packet_finalize_delta < packet_interval_min,
        "Finalize delta {} must be smaller than the min packet interval {}",
        ns_to_str(packet_finalize_delta),
        ns_to_str(packet_interval_min),
    );
    // TODO if the packet_interval is long, and packet length was not explicitly set, we should
    // automaticaly set it to a shorter value to decrease latency.
    WireConfig {
        packet_length,
        packet_interval_min,
        packet_interval_max,
        packet_finalize_delta,
    }
}

pub(crate) fn to_wire_configs(
    peer: &SocketAddr,
    wire_configuration: &WireConfigCli,
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
