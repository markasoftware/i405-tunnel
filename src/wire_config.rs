use std::{net::SocketAddr, time::Duration};

use crate::config_cli::{AverageWireIntervalCli, WireConfigCli, WireIntervalCli};
use crate::constants::MAX_IP_PACKET_LENGTH;
use crate::jitter::Jitterator;
use crate::utils::ns_to_str;

/// What fraction of the interval's average length should be the jitter, when the user doesn't
/// explicitly specify jitter?
const DEFAULT_JITTER_FRACTION: f64 = 0.25;
/// Do not allow the interval length lower bound to be less than this.
const MIN_MIN_INTERVAL: u64 = 50_000;
/// If not overridden by user, timeout is computed as max(MIN_DEFAULT_TIMEOUT,
/// MIN_DEFAULT_PACKET_TIMEOUTS*incoming_packet_interval_max)
pub(crate) const MIN_DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const MIN_DEFAULT_TIMEOUT_PACKETS: u64 = 100;

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct WireConfig {
    /// This is the length of the outgoing inner I405 packets, not IP packets
    pub(crate) packet_length: u16,
    /// minimum duration between outgoing packets
    pub(crate) packet_interval_min: u64,
    /// Maximum duration between outgoing packets
    pub(crate) packet_interval_max: u64,
    /// How long to finish preparing an outgoing packet before calling hardware.send_outgoing (WIP)
    pub(crate) packet_finalize_delta: u64,
    /// A bit misleading -- the rest of the WireConfig describes the outgoing connection, but the
    /// timeout represents how long we'll wait for an incoming message before timing out. So it's
    /// more accurate to think of a WireConfig as describing "everything one side of the connection
    /// needs to know in order to properly run an established connection", rather than "settings for
    /// the outgoing half of a connection"
    pub(crate) timeout: u64,
}

pub(crate) struct WireConfigs {
    pub(crate) client: WireConfig,
    pub(crate) server: WireConfig,
}

impl WireConfig {
    /// Always constructs a new jitterator, no singleton logic
    pub(crate) fn jitterator(&self) -> Jitterator {
        Jitterator::new(self.packet_interval_min, self.packet_interval_max)
    }
}

// just a helper used as intermediate return value
struct PartialWireConfig {
    packet_length: u16,
    packet_interval_min: u64,
    packet_interval_max: u64,
}

impl PartialWireConfig {
    fn new(
        c2s_or_s2c: &str,
        interface_name: &str,
        mtu: u16,
        user_ip_packet_length: Option<u64>,
        interval: &WireIntervalCli,
    ) -> PartialWireConfig {
        let packet_length: u16 = user_ip_packet_length
            .map(|pl| {
                pl.try_into()
                    .expect(&format!("Packet length {pl} is too long; must be <={}", u16::MAX))
            })
            .unwrap_or_else(|| {
                log::info!(
                    "Using MTU as packet length: {mtu} (on interface {interface_name}), because no explicit {c2s_or_s2c} packet length was specified"
                );
                mtu
            });
        if packet_length > mtu {
            log::warn!(
                "Specified {c2s_or_s2c} packet length {packet_length} bytes is greater than the MTU of {mtu} (on interface {interface_name}), so IP fragmentation may occur -- we'll continue anyway, but choose a smaller packet length for better performance."
            );
        }
        let average_interval: u64 = match interval.average_interval {
            // TODO print the computed speed from the interval. Or maybe, just print the whole goddamn
            // config for both directions as well as the speed, since we always need to print something.
            AverageWireIntervalCli::Fixed(fixed_interval) => fixed_interval,
            AverageWireIntervalCli::Rate(bytes_per_second) => {
                u64::from(packet_length) * 1_000_000_000 / bytes_per_second
            }
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
            "Computed {} packet intervals (w/ jitter) will be between {} and {}",
            c2s_or_s2c,
            ns_to_str(packet_interval_min),
            ns_to_str(packet_interval_max)
        );
        assert!(
            packet_interval_min >= MIN_MIN_INTERVAL,
            "Min packet interval {} is too small must be at least {}. I405 won't be able to consistently dispatch packets at the right time, which can compromise privacy. Try setting a lower bandwidth / higher inter-packet interval.",
            ns_to_str(packet_interval_min),
            ns_to_str(MIN_MIN_INTERVAL),
        );
        // TODO if the packet_interval is long, and packet length was not explicitly set, we should
        // automaticaly set it to a shorter value to decrease latency.
        PartialWireConfig {
            packet_length,
            packet_interval_min,
            packet_interval_max,
        }
    }

    /// Fill in the last bit of info needed to make it a full wire config
    fn to_wire_config(
        &self,
        other: &PartialWireConfig,
        user_timeout: Option<Duration>,
        packet_finalize_delta: u64,
    ) -> WireConfig {
        assert!(
            packet_finalize_delta < self.packet_interval_min,
            "Finalize delta {} must be smaller than the min packet interval {}",
            ns_to_str(packet_finalize_delta),
            ns_to_str(self.packet_interval_min),
        );
        let timeout: u64 = match user_timeout {
            Some(user_timeout) => user_timeout.as_nanos().try_into().unwrap(),
            None => std::cmp::max(
                MIN_DEFAULT_TIMEOUT.as_nanos().try_into().unwrap(),
                MIN_DEFAULT_TIMEOUT_PACKETS * other.packet_interval_max,
            ),
        };
        WireConfig {
            packet_length: self.packet_length,
            packet_interval_min: self.packet_interval_min,
            packet_interval_max: self.packet_interval_max,
            packet_finalize_delta,
            timeout,
        }
    }
}

pub(crate) fn to_wire_configs(peer: &SocketAddr, wire_config_cli: &WireConfigCli) -> WireConfigs {
    let (interface_name, mtu_usize) =
        mtu::interface_and_mtu(peer.ip()).expect("Error computing interface MTU");
    let mtu = mtu_usize
        .try_into()
        .unwrap_or(u16::MAX)
        .clamp(0, MAX_IP_PACKET_LENGTH.try_into().unwrap());

    let client_partial = PartialWireConfig::new(
        "client-to-server",
        &interface_name,
        mtu,
        wire_config_cli.outgoing_packet_length,
        &wire_config_cli.outgoing_interval,
    );
    let server_partial = PartialWireConfig::new(
        "server-to-client",
        &interface_name,
        mtu,
        wire_config_cli.incoming_packet_length,
        &wire_config_cli.incoming_interval,
    );
    let client_wire_config = client_partial.to_wire_config(
        &server_partial,
        wire_config_cli.client_timeout,
        wire_config_cli.outgoing_finalize_delta,
    );
    let server_wire_config = server_partial.to_wire_config(
        &client_partial,
        wire_config_cli.server_timeout,
        wire_config_cli.incoming_finalize_delta,
    );

    WireConfigs {
        client: client_wire_config,
        server: server_wire_config,
    }
}

// ai generated tests, deal with it
#[cfg(test)]
mod test {
    use super::*;
    use crate::config_cli::{AverageWireIntervalCli, WireIntervalCli};

    fn fixed_interval(average_interval: u64, jitter: Option<u64>) -> WireIntervalCli {
        WireIntervalCli {
            average_interval: AverageWireIntervalCli::Fixed(average_interval),
            jitter,
        }
    }

    fn rate_interval(bytes_per_second: u64, jitter: Option<u64>) -> WireIntervalCli {
        WireIntervalCli {
            average_interval: AverageWireIntervalCli::Rate(bytes_per_second),
            jitter,
        }
    }

    #[test]
    fn partial_wire_config_default_packet_length() {
        let config =
            PartialWireConfig::new("test", "lo", 1500, None, &fixed_interval(1_000_000, None));
        assert_eq!(config.packet_length, 1500);
        assert_eq!(config.packet_interval_min, 750_000); // 1_000_000 - 1_000_000 * 0.25
        assert_eq!(config.packet_interval_max, 1_250_000); // 1_000_000 + 1_000_000 * 0.25
    }

    #[test]
    fn partial_wire_config_specified_packet_length() {
        let config = PartialWireConfig::new(
            "test",
            "lo",
            1500,
            Some(1000),
            &fixed_interval(1_000_000, None),
        );
        assert_eq!(config.packet_length, 1000);
    }

    #[test]
    fn partial_wire_config_fixed_interval_with_jitter() {
        let config = PartialWireConfig::new(
            "test",
            "lo",
            1500,
            None,
            &fixed_interval(1_000_000, Some(100_000)),
        );
        assert_eq!(config.packet_interval_min, 900_000);
        assert_eq!(config.packet_interval_max, 1_100_000);
    }

    #[test]
    #[should_panic(
        expected = "Specified jitter of 1ms 100us is larger than the average inter-packet interval 1ms"
    )]
    fn partial_wire_config_fixed_interval_jitter_too_large() {
        PartialWireConfig::new(
            "test",
            "lo",
            1500,
            None,
            &fixed_interval(1_000_000, Some(1_100_000)),
        );
    }

    #[test]
    fn partial_wire_config_rate_interval_no_jitter() {
        // Rate: 1400 bytes / (target_interval_ns / 1_000_000_000) = bytes_per_second
        // target_interval_ns = 1400 * 1_000_000_000 / bytes_per_second
        // target_interval_ns = 1400 * 1_000_000_000 / 1_400_000 = 1_000_000 ns
        let config = PartialWireConfig::new(
            "test",
            "lo",
            1500,
            None,
            &rate_interval(1_500_000, None), // 1.4 MB/s
        );
        assert_eq!(config.packet_interval_min, 750_000);
        assert_eq!(config.packet_interval_max, 1_250_000);
    }

    #[test]
    fn partial_wire_config_rate_interval_with_jitter() {
        let config = PartialWireConfig::new(
            "test",
            "lo",
            1500,
            Some(500),
            &rate_interval(250_000, Some(50_000)), // 0.25 MB/s
                                                   // average interval = 500 * 1_000_000_000 / 250_000 = 2_000_000 ns
        );
        assert_eq!(config.packet_interval_min, 1_950_000); // 2_000_000 - 50_000
        assert_eq!(config.packet_interval_max, 2_050_000); // 2_000_000 + 50_000
    }

    #[test]
    #[should_panic(expected = "Min packet interval 40us is too small must be at least 50us.")]
    fn partial_wire_config_min_interval_too_small() {
        PartialWireConfig::new(
            "test",
            "lo",
            1500,
            None,
            // average 50_000, default jitter is 0.25 * 50_000 = 12_500
            // min = 50_000 - 12_500 = 37_500. This is less than MIN_MIN_INTERVAL (50_000)
            &fixed_interval(MIN_MIN_INTERVAL, Some(MIN_MIN_INTERVAL / 5)), // jitter 10_000 -> min 40_000
        );
    }

    #[test]
    fn to_wire_config_default_timeout() {
        let partial =
            PartialWireConfig::new("test", "lo", 1500, None, &fixed_interval(1_000_000, None));
        let config = partial.to_wire_config(&partial, None, 100_000);
        assert_eq!(partial.packet_length, config.packet_length);
        assert_eq!(partial.packet_interval_min, config.packet_interval_min);
        assert_eq!(partial.packet_interval_max, config.packet_interval_max);
        assert_eq!(config.packet_finalize_delta, 100_000);
        // the interval is small enough that it should use the default
        assert_eq!(
            config.timeout,
            MIN_DEFAULT_TIMEOUT.as_nanos().try_into().unwrap()
        );
    }

    #[test]
    fn to_wire_config_default_timeout_2() {
        let partial = PartialWireConfig::new(
            "test",
            "lo",
            1500,
            None,
            &fixed_interval(1_000_000_000, Some(500)),
        );
        let config = partial.to_wire_config(&partial, None, 100_000);
        assert_eq!(
            config.timeout,
            MIN_DEFAULT_TIMEOUT_PACKETS * (1_000_000_000 + 500)
        );
    }

    #[test]
    fn to_wire_config_user_timeout() {
        let partial = PartialWireConfig::new(
            "test",
            "lo",
            1500,
            None,
            &fixed_interval(1_000_000_000, Some(500)),
        );
        let config = partial.to_wire_config(&partial, Some(Duration::from_secs(2)), 100_000);
        assert_eq!(config.timeout, 2_000_000_000);
    }

    #[test]
    #[should_panic(
        expected = "Finalize delta 100us must be smaller than the min packet interval 75us"
    )]
    fn to_wire_config_finalize_delta_too_large() {
        let partial = PartialWireConfig::new(
            "test",
            "lo",
            1500,
            None,
            &fixed_interval(100_000, None), // min interval will be 75_000
        );
        partial.to_wire_config(&partial, None, 100_000);
    }
}
