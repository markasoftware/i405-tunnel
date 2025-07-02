/// The bulk of "integration"-style tests go here. We use a "simulated" Hardware so everything's
/// super fast and reproducible. We also have some true integration tests that set up Linux network
/// netspaces and crap, but it's much easier to mess with stuff and assert stuff here.
use crate::array_array::IpPacketBuffer;
use crate::constants::{IPV4_HEADER_LENGTH, UDP_HEADER_LENGTH};
use crate::core::{self, Core};
use crate::hardware::simulated::{LocalPacket, SimulatedHardware, WanPacket};
use crate::utils::ip_to_i405_length;
use crate::wire_config::WireConfig;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::Duration;

use test_case::test_matrix;

const PSK: &[u8] = b"password";
const TIMEOUT: u64 = 1_000_000_000;
// in case this cursed knowledge is useful when the fragmentation test some day fails: This used to
// be the inner, i405 packet length rather than the outer ip packet length that it is now.
const DEFAULT_PACKET_LENGTH: u16 = 1000;
const DEFAULT_CLIENT_WIRE_CONFIG: WireConfig = WireConfig {
    packet_length: DEFAULT_PACKET_LENGTH,
    packet_interval_min: 1_423_000, // 1.423ms
    packet_interval_max: 1_423_000, // 1.423ms
    packet_finalize_delta: 100_000,
    timeout: TIMEOUT,
};
const DEFAULT_SERVER_WIRE_CONFIG: WireConfig = WireConfig {
    packet_length: DEFAULT_PACKET_LENGTH,
    packet_interval_min: 1_411_000, // 1.411ms
    packet_interval_max: 1_411_000, // 1.411ms
    packet_finalize_delta: 100_000,
    timeout: TIMEOUT,
};
const LONGER_CLIENT_WIRE_CONFIG: WireConfig = WireConfig {
    packet_length: DEFAULT_PACKET_LENGTH,
    packet_interval_min: 142_300_000, // 142.3ms
    packet_interval_max: 142_300_000, // 142.3ms
    packet_finalize_delta: 100_000,
    timeout: TIMEOUT,
};
const LONGER_SERVER_WIRE_CONFIG: WireConfig = WireConfig {
    packet_length: DEFAULT_PACKET_LENGTH,
    packet_interval_min: 141_100_000, // 141.1ms
    packet_interval_max: 141_100_000, // 141.1ms
    packet_finalize_delta: 100_000,
    timeout: TIMEOUT,
};
const JITTERED_CLIENT_WIRE_CONFIG: WireConfig = WireConfig {
    packet_length: DEFAULT_PACKET_LENGTH,
    packet_interval_min: 1_400_000,
    packet_interval_max: 1_500_000,
    packet_finalize_delta: 100_000,
    timeout: TIMEOUT,
};
const JITTERED_SERVER_WIRE_CONFIG: WireConfig = WireConfig {
    packet_length: DEFAULT_PACKET_LENGTH,
    packet_interval_min: 1_700_000,
    packet_interval_max: 1_800_000,
    packet_finalize_delta: 100_000,
    timeout: TIMEOUT,
};

fn ms(ms: f64) -> u64 {
    (ms * 1_000_000.0).round() as u64
}

fn client_addr() -> SocketAddr {
    "10.140.5.1:1405".parse().unwrap()
}

fn server_addr() -> SocketAddr {
    "10.140.5.2:1405".parse().unwrap()
}

fn simulated_pair(
    client_wire_config: WireConfig,
    server_wire_config: WireConfig,
    default_delay: u64,
) -> (SimulatedHardware, BTreeMap<SocketAddr, core::ConcreteCore>) {
    let mut simulated_hardware =
        SimulatedHardware::new(vec![client_addr(), server_addr()], default_delay);
    let server_core = core::server::Core::new(
        core::server::Config {
            pre_shared_key: PSK.into(),
        },
        &mut simulated_hardware.hardware(server_addr()),
    )
    .unwrap();
    let client_core = core::client::Core::new(
        core::client::Config {
            pre_shared_key: PSK.into(),
            peer_address: server_addr(),
            client_wire_config,
            server_wire_config,
        },
        &mut simulated_hardware.hardware(client_addr()),
    )
    .unwrap();
    let cores = BTreeMap::from([
        (client_addr(), client_core.into()),
        (server_addr(), server_core.into()),
    ]);
    (simulated_hardware, cores)
}

fn default_simulated_pair(
    default_delay: u64,
) -> (SimulatedHardware, BTreeMap<SocketAddr, core::ConcreteCore>) {
    simulated_pair(
        DEFAULT_CLIENT_WIRE_CONFIG,
        DEFAULT_SERVER_WIRE_CONFIG,
        default_delay,
    )
}

/// a packet of given length
fn long_packet(length: usize) -> IpPacketBuffer {
    let mut packet_vec = Vec::new();
    for i in 0..length {
        packet_vec.push((i % usize::from(u8::MAX)).try_into().unwrap());
    }
    IpPacketBuffer::new(&packet_vec)
}

fn setup_logging() {
    // this is a bit hacky because it initializes it for other tests that may run after ours, even
    // if it causes undue overhead. But logging shouldn't ever be that slow anyway.
    let _ = env_logger::builder().is_test(true).try_init();
}

/// Test a simple connection (which, to be honest, still isn't very simple): DTLS handshake, I405
/// handshake, and then a few packets each way.
#[test]
fn simple() {
    setup_logging();
    let (mut simulated_hardware, mut cores) = default_simulated_pair(0);

    assert!(simulated_hardware.qdisc_settings(&client_addr()).is_some());
    assert!(simulated_hardware.qdisc_settings(&server_addr()).is_none());

    simulated_hardware.make_outgoing_packet(&client_addr(), &[1, 4, 0, 5]);
    simulated_hardware.make_outgoing_packet(&server_addr(), &[4, 3, 2, 1]);
    // at 1.411ms, the server hasn't yet gotten the first "normal" packet from the client, so it's
    // not going to send anything outgoing until 2.822.
    simulated_hardware.run_until(&mut cores, ms(3.0));

    assert!(simulated_hardware.qdisc_settings(&server_addr()).is_some());
    // bullshit check to help ensure we didn't mix up outgoing/incoming packet sizes
    assert_ne!(
        simulated_hardware.qdisc_settings(&client_addr()).unwrap(),
        simulated_hardware.qdisc_settings(&server_addr()).unwrap()
    );

    assert_eq!(
        simulated_hardware.sent_incoming_packets(&client_addr()),
        &vec![LocalPacket {
            buffer: IpPacketBuffer::new(&[4, 3, 2, 1]),
            // 1.423 = time for the initial handshake, then 1.411 = interval after that
            timestamp: ms(1.423 + 1.411),
        }]
    );
    assert_eq!(
        simulated_hardware.sent_incoming_packets(&server_addr()),
        &vec![LocalPacket {
            buffer: IpPacketBuffer::new(&[1, 4, 0, 5]),
            timestamp: ms(1.423),
        }]
    );

    simulated_hardware.make_outgoing_packet(&client_addr(), &[7]);
    simulated_hardware.run_until(&mut cores, ms(4.5));

    assert_eq!(
        simulated_hardware
            .sent_incoming_packets(&server_addr())
            .len(),
        2
    );
    assert_eq!(
        simulated_hardware.sent_incoming_packets(&server_addr())[1],
        LocalPacket {
            buffer: IpPacketBuffer::new(&[7]),
            timestamp: ms(1.423 * 3.0),
        }
    );
}

#[test]
fn fragmentation() {
    setup_logging();
    let (mut simulated_hardware, mut cores) = default_simulated_pair(0);

    let packet = long_packet(1200);

    simulated_hardware.run_until(&mut cores, ms(1.0));
    simulated_hardware.make_outgoing_packet(&server_addr(), &packet);
    simulated_hardware.run_until(&mut cores, ms(3.0));
    assert!(
        simulated_hardware
            .sent_incoming_packets(&client_addr())
            .is_empty()
    );
    simulated_hardware.run_until(&mut cores, ms(4.5));
    assert_eq!(
        simulated_hardware.sent_incoming_packets(&client_addr()),
        &vec![LocalPacket {
            buffer: packet,
            timestamp: ms(1.423 + 1.411 * 2.0),
        }]
    );
}

/// Test that packets over the WAN are actually the correct size
#[test]
fn wan_packet_length() {
    setup_logging();
    let (mut simulated_hardware, mut cores) = default_simulated_pair(0);

    let dtls_packet_length: usize =
        usize::from(DEFAULT_PACKET_LENGTH - IPV4_HEADER_LENGTH - UDP_HEADER_LENGTH - 12);

    simulated_hardware.run_until(&mut cores, 1);
    let handshake = simulated_hardware.all_wan_packets();
    let num_handshake_packets = handshake.len();
    // for sanity, check that the first packet is smaller than we requested, because it should just
    // be a ClientHello.
    assert!(handshake[0].buffer.len() < dtls_packet_length);
    // the last two should be handshakes, and of the correct size
    assert_eq!(
        handshake[handshake.len() - 1].buffer.len(),
        dtls_packet_length
    );
    assert_eq!(
        handshake[handshake.len() - 2].buffer.len(),
        dtls_packet_length
    );

    simulated_hardware.run_until(&mut cores, ms(3.0));
    let empty_packets = simulated_hardware.all_wan_packets();
    let num_empty_packets = empty_packets.len();
    // just so this test doesn't get stale if others change
    assert_eq!(num_handshake_packets + 3, num_empty_packets);
    // make sure actual data packets
    assert_eq!(
        empty_packets[empty_packets.len() - 1].buffer.len(),
        dtls_packet_length
    );
    assert_eq!(
        empty_packets[empty_packets.len() - 2].buffer.len(),
        dtls_packet_length
    );
    assert_eq!(
        empty_packets[empty_packets.len() - 3].buffer.len(),
        dtls_packet_length
    );

    // now send an actual, large packet and make sure the size is the same
    simulated_hardware.make_outgoing_packet(&client_addr(), &long_packet(1200));
    simulated_hardware.run_until(&mut cores, ms(4.5));
    let full_packets = simulated_hardware.all_wan_packets();
    assert_eq!(num_empty_packets + 2, full_packets.len());
    assert_eq!(
        full_packets[full_packets.len() - 1].buffer.len(),
        dtls_packet_length
    );
    assert_eq!(
        full_packets[full_packets.len() - 2].buffer.len(),
        dtls_packet_length
    );
}

/// Test that we can pack multiple packets into the same network packet when they fit.
#[test]
fn packing() {
    setup_logging();

    // type byte and length only
    const MESSAGE_HEADER_LENGTH: usize = 1 + 2;
    let i405_packet_length = usize::from(ip_to_i405_length(DEFAULT_PACKET_LENGTH, server_addr()));
    let first_message_length: usize = i405_packet_length / 2;
    let second_message_length: usize =
        i405_packet_length - MESSAGE_HEADER_LENGTH * 2 - first_message_length;

    let (mut simulated_hardware, mut cores) = default_simulated_pair(0);
    simulated_hardware.make_outgoing_packet(&client_addr(), &long_packet(first_message_length));
    simulated_hardware.make_outgoing_packet(&client_addr(), &long_packet(second_message_length));

    simulated_hardware.run_until(&mut cores, 1);
    assert!(
        simulated_hardware
            .sent_incoming_packets(&server_addr())
            .is_empty()
    );
    // this is just FUD to make sure it somehow doesn't send multiple packets TODO consider adding
    // some global thing so if in /any/ of our tests it sends packets when it shouldn't, or of the
    // wrong size, it errors out, rather than needing to check on a test-by-test basis.
    let num_handshake_wan_packets = simulated_hardware.all_wan_packets().len();
    simulated_hardware.run_until(&mut cores, ms(3.0));
    assert_eq!(
        simulated_hardware.all_wan_packets().len(),
        num_handshake_wan_packets + 3
    );
    // we'll verify the actual contents later
    assert_eq!(
        simulated_hardware
            .sent_incoming_packets(&server_addr())
            .len(),
        2
    );

    // now test that it /doesn't/ work when we make it one larger
    simulated_hardware.make_outgoing_packet(&client_addr(), &long_packet(first_message_length));
    simulated_hardware
        .make_outgoing_packet(&client_addr(), &long_packet(second_message_length + 1));
    simulated_hardware.run_until(&mut cores, ms(5.0));
    // just fud because I don't fully trust the SimulatedHardware yet
    assert_eq!(
        simulated_hardware
            .sent_incoming_packets(&server_addr())
            .len(),
        3
    );
    simulated_hardware.run_until(&mut cores, ms(6.0));

    assert_eq!(
        simulated_hardware.sent_incoming_packets(&server_addr()),
        &vec![
            LocalPacket {
                buffer: long_packet(first_message_length),
                timestamp: ms(1.423),
            },
            LocalPacket {
                buffer: long_packet(second_message_length),
                timestamp: ms(1.423),
            },
            LocalPacket {
                buffer: long_packet(first_message_length),
                timestamp: ms(1.423 * 3.0),
            },
            LocalPacket {
                buffer: long_packet(second_message_length + 1),
                timestamp: ms(1.423 * 4.0),
            },
        ]
    );
}

fn inter_packet_intervals(packets: &[WanPacket]) -> Vec<u64> {
    let mut result = Vec::new();
    let mut last_time = None;
    for packet in packets {
        if let Some(last_time) = last_time {
            result.push(packet.sent_timestamp - last_time);
        }
        last_time = Some(packet.sent_timestamp);
    }
    result
}

/// Assert that the min of vec is at least as small as `min`, similarly for `max`, and that the
/// average is within the given range.
fn assert_statistics(vec: Vec<u64>, min: u64, max: u64, average_range: std::ops::Range<f64>) {
    let actual_min = vec.iter().min().unwrap();
    let actual_max = vec.iter().max().unwrap();
    let actual_avg = vec.iter().sum::<u64>() as f64 / vec.len() as f64;
    assert!(
        actual_min <= &min,
        "Expected min: {min}, Actual min: {actual_min}"
    );
    assert!(
        actual_max >= &max,
        "Expected max: {max}, Actual max: {actual_max}"
    );
    assert!(
        average_range.contains(&actual_avg),
        "Actual average {actual_avg} was not in range {average_range:?}"
    );
}

#[test]
fn jitter() {
    setup_logging();
    let (mut simulated_hardware, mut cores) =
        simulated_pair(JITTERED_CLIENT_WIRE_CONFIG, JITTERED_SERVER_WIRE_CONFIG, 0);

    // should involve on the order of 10,000 packets going either way, which is a large enough N
    // that jitter stats should be good
    simulated_hardware.run_until(&mut cores, ms(10_000.0));

    // skip first 100 on either side so we make sure not to capture the handshake in our statistics
    let c2s_intervals =
        inter_packet_intervals(&simulated_hardware.sent_outgoing_packets(&client_addr())[100..]);
    let s2c_intervals =
        inter_packet_intervals(&simulated_hardware.sent_outgoing_packets(&server_addr())[100..]);

    log::info!(
        "c2s packet count: {}, c2s_intervals length: {}",
        simulated_hardware
            .sent_incoming_packets(&server_addr())
            .len(),
        c2s_intervals.len()
    );

    assert_statistics(
        c2s_intervals,
        1_410_000,
        1_490_000,
        1_445_000.0..1_455_000.0,
    );
    assert_statistics(
        s2c_intervals,
        1_710_000,
        1_790_000,
        1_745_000.0..1_755_000.0,
    );
}

#[test]
#[ignore]
fn drop_and_reorder() {
    setup_logging();
    let mut simulated_hardware =
        SimulatedHardware::new(vec![client_addr(), server_addr()], ms(1.0));
    simulated_hardware.drop_packet(0);
    simulated_hardware.drop_packet(2);
    simulated_hardware.delay_packet(3, ms(500.0));
    simulated_hardware.delay_packet(4, ms(1500.0));
    let server_core = core::server::Core::new(
        core::server::Config {
            pre_shared_key: PSK.into(),
        },
        &mut simulated_hardware.hardware(server_addr()),
    )
    .unwrap();
    let client_core = core::client::Core::new(
        core::client::Config {
            pre_shared_key: PSK.into(),
            peer_address: server_addr(),
            client_wire_config: DEFAULT_CLIENT_WIRE_CONFIG,
            server_wire_config: DEFAULT_SERVER_WIRE_CONFIG,
        },
        &mut simulated_hardware.hardware(client_addr()),
    )
    .unwrap();
    let mut cores = BTreeMap::from([
        (client_addr(), client_core.into()),
        (server_addr(), server_core.into()),
    ]);

    simulated_hardware.make_outgoing_packet(&client_addr(), &[1, 4, 0, 5]);
    simulated_hardware.make_outgoing_packet(&server_addr(), &[4, 3, 2, 1]);
    // depending on the implementation, it can reasonably send the first packet before reading the
    // outgoing packet (in fact, that's what the current implementation does), so we need to wait
    // long enough that it can actually read the outgoing packet. This is long enough for two
    // packets.
    simulated_hardware.run_until(&mut cores, ms(1500.1));
    assert!(
        simulated_hardware
            .sent_incoming_packets(&client_addr())
            .is_empty()
    );
    assert!(
        simulated_hardware
            .sent_incoming_packets(&server_addr())
            .is_empty()
    );

    std::thread::sleep(Duration::from_millis(1010));
    simulated_hardware.run_until(&mut cores, ms(6000.0));
    let client_incoming_packets = simulated_hardware.sent_incoming_packets(&client_addr());
    let server_incoming_packets = simulated_hardware.sent_incoming_packets(&server_addr());
    assert_eq!(client_incoming_packets.len(), 1);
    assert_eq!(server_incoming_packets.len(), 1);
    assert_eq!(&client_incoming_packets[0].buffer[..], &[4, 3, 2, 1]);
    assert_eq!(&server_incoming_packets[0].buffer[..], &[1, 4, 0, 5]);
}

// Test to ensure that we can handle a handshake packet in established mode
// TODO unignore once wolfssl fixes are released
#[test_matrix(0..15, 0..15, (false, true))]
#[ignore]
#[cfg(any())]
fn long_distance_reorder(packet_1: u64, packet_2: u64, reorder_1st_instead_of_drop: bool) {
    #[cfg(feature = "wolfssl-debug")]
    wolfssl::enable_debugging(true);

    setup_logging();
    // TODO factor out the hardware and core creation into something where we can pass in a lambda doing delays
    let mut simulated_hardware =
        SimulatedHardware::new(vec![client_addr(), server_addr()], ms(1.0));
    if reorder_1st_instead_of_drop {
        simulated_hardware.delay_packet(packet_1, ms(2000.0));
    } else {
        simulated_hardware.drop_packet(packet_1);
    }
    if packet_1 != packet_2 {
        simulated_hardware.drop_packet(packet_2);
    }
    let server_core = core::server::Core::new(
        core::server::Config {
            pre_shared_key: PSK.into(),
        },
        &mut simulated_hardware.hardware(server_addr()),
    )
    .unwrap();
    let client_core = core::client::Core::new(
        core::client::Config {
            pre_shared_key: PSK.into(),
            peer_address: server_addr(),
            client_wire_config: LONGER_CLIENT_WIRE_CONFIG,
            server_wire_config: LONGER_SERVER_WIRE_CONFIG,
        },
        &mut simulated_hardware.hardware(client_addr()),
    )
    .unwrap();
    let mut cores = BTreeMap::from([
        (client_addr(), client_core.into()),
        (server_addr(), server_core.into()),
    ]);

    let mut next_time = ms(2000.0);

    // I'm not sure why so many roundtrips are needed. Try reducing it, and you'll see there's a
    // couple cases (drop 2,6, and then reorder 2,5) that need substantially more timeouts than the
    // others to complete. Who knows??
    for _ in 0..7 {
        simulated_hardware.run_until(&mut cores, next_time);
        std::thread::sleep(Duration::from_millis(1010));
        next_time += ms(2000.0);
    }

    // send a packet to ensure we are actually in established mode
    simulated_hardware.make_outgoing_packet(&client_addr(), &[1, 4, 0, 5]);
    simulated_hardware.run_until(&mut cores, next_time);
    assert_eq!(simulated_hardware.incoming_packets(&server_addr()).len(), 1);
}

#[test]
fn wrong_psk() {
    setup_logging();
    let mut simulated_hardware =
        SimulatedHardware::new(vec![client_addr(), server_addr()], ms(1.0));
    let server_core = core::server::Core::new(
        core::server::Config {
            pre_shared_key: PSK.into(),
        },
        &mut simulated_hardware.hardware(server_addr()),
    )
    .unwrap();
    let client_core = core::client::Core::new(
        core::client::Config {
            pre_shared_key: "wrong password".into(),
            peer_address: server_addr(),
            client_wire_config: DEFAULT_CLIENT_WIRE_CONFIG,
            server_wire_config: DEFAULT_SERVER_WIRE_CONFIG,
        },
        &mut simulated_hardware.hardware(client_addr()),
    )
    .unwrap();
    let mut cores = BTreeMap::from([
        (client_addr(), client_core.into()),
        (server_addr(), server_core.into()),
    ]);

    simulated_hardware.run_until(&mut cores, ms(1.0));

    assert!(
        simulated_hardware
            .sent_incoming_packets(&server_addr())
            .is_empty()
    );
    assert!(
        simulated_hardware
            .sent_incoming_packets(&client_addr())
            .is_empty()
    );
}

// Test one client connecting with the wrong password, and another who starts later, with the
// correct password, the second one should win.
#[test]
fn multiple_ongoing_negotiations() {
    setup_logging();
    let evil_client_addr = "10.140.5.10:1405".parse().unwrap();
    let good_client_addr = "10.140.5.20:1405".parse().unwrap();
    let mut simulated_hardware = SimulatedHardware::new(
        vec![good_client_addr, evil_client_addr, server_addr()],
        ms(1.0),
    );
    let server_core = core::server::Core::new(
        core::server::Config {
            pre_shared_key: PSK.into(),
        },
        &mut simulated_hardware.hardware(server_addr()),
    )
    .unwrap();
    let evil_client_core = core::client::Core::new(
        core::client::Config {
            pre_shared_key: "wrong password".into(),
            peer_address: server_addr(),
            client_wire_config: DEFAULT_CLIENT_WIRE_CONFIG,
            server_wire_config: DEFAULT_SERVER_WIRE_CONFIG,
        },
        &mut simulated_hardware.hardware(evil_client_addr),
    )
    .unwrap();
    let noop_core =
        core::noop::Core::new(&mut simulated_hardware.hardware(good_client_addr)).unwrap();
    let mut cores = BTreeMap::from([
        (evil_client_addr, evil_client_core.into()),
        (good_client_addr, noop_core.into()),
        (server_addr(), server_core.into()),
    ]);

    // should be partway through the negotiation by now
    simulated_hardware.run_until(&mut cores, ms(4.0));

    let good_client_core = core::client::Core::new(
        core::client::Config {
            pre_shared_key: PSK.into(),
            peer_address: server_addr(),
            client_wire_config: DEFAULT_CLIENT_WIRE_CONFIG,
            server_wire_config: DEFAULT_SERVER_WIRE_CONFIG,
        },
        &mut simulated_hardware.hardware(good_client_addr),
    )
    .unwrap();
    cores.insert(good_client_addr, good_client_core.into());
    simulated_hardware.run_until(&mut cores, ms(15.0));

    // ensure that we can communicate on the good core
    simulated_hardware.make_outgoing_packet(&server_addr(), &[1, 4, 0, 5]);
    simulated_hardware.run_until(&mut cores, ms(20.0));
    assert_eq!(
        simulated_hardware
            .sent_incoming_packets(&good_client_addr)
            .len(),
        1
    );
    assert!(
        simulated_hardware
            .sent_incoming_packets(&evil_client_addr)
            .is_empty()
    );
}

#[test]
fn client_termination_and_reconnect() {
    setup_logging();
    let (mut simulated_hardware, mut cores) = default_simulated_pair(0);

    // send a packet just to ensure it actually establishes connection the first time.
    simulated_hardware.make_outgoing_packet(&client_addr(), &[1, 4, 0, 5]);
    simulated_hardware.run_until(&mut cores, ms(2.0));
    assert_eq!(
        simulated_hardware
            .sent_incoming_packets(&server_addr())
            .len(),
        1
    );

    let original_client_core = cores.insert(
        client_addr(),
        core::noop::Core::new(&mut simulated_hardware.hardware(client_addr()))
            .unwrap()
            .into(),
    );
    original_client_core
        .unwrap()
        .on_terminate(&mut simulated_hardware.hardware(client_addr()));
    let new_client_core = core::client::Core::new(
        core::client::Config {
            pre_shared_key: PSK.into(),
            peer_address: server_addr(),
            client_wire_config: DEFAULT_CLIENT_WIRE_CONFIG,
            server_wire_config: DEFAULT_SERVER_WIRE_CONFIG,
        },
        &mut simulated_hardware.hardware(client_addr()),
    )
    .unwrap();
    cores.insert(client_addr(), new_client_core.into());

    simulated_hardware.run_until(&mut cores, ms(2.001));
    simulated_hardware.make_outgoing_packet(&client_addr(), &[5, 0, 4, 1]);
    simulated_hardware.run_until(&mut cores, ms(4.0));
    assert_eq!(
        simulated_hardware
            .sent_incoming_packets(&server_addr())
            .len(),
        2
    );
}

#[test]
fn server_termination_and_reconnect() {
    setup_logging();
    let (mut simulated_hardware, mut cores) = default_simulated_pair(0);

    // send a packet just to ensure it actually establishes connection the first time.
    simulated_hardware.make_outgoing_packet(&client_addr(), &[1, 4, 0, 5]);
    simulated_hardware.run_until(&mut cores, ms(2.0));
    assert_eq!(
        simulated_hardware
            .sent_incoming_packets(&server_addr())
            .len(),
        1
    );

    let original_server_core = cores.insert(
        server_addr(),
        core::noop::Core::new(&mut simulated_hardware.hardware(server_addr()))
            .unwrap()
            .into(),
    );
    original_server_core
        .unwrap()
        .on_terminate(&mut simulated_hardware.hardware(server_addr()));
    let new_server_core = core::server::Core::new(
        core::server::Config {
            pre_shared_key: PSK.into(),
        },
        &mut simulated_hardware.hardware(server_addr()),
    )
    .unwrap();
    cores.insert(server_addr(), new_server_core.into());

    // whether the simulated core will process incoming or outgoing packets first is indeterminate,
    // and if it processes this outgoing packet first, then it will start preparing a packet to fire
    // off, then immediately discard it. So we want to wait to enqueue any packets until the new
    // connection is made.
    simulated_hardware.run_until(&mut cores, ms(2.001));
    simulated_hardware.make_outgoing_packet(&client_addr(), &[5, 0, 4, 1]);
    simulated_hardware.run_until(&mut cores, ms(4.0));
    assert_eq!(
        simulated_hardware
            .sent_incoming_packets(&server_addr())
            .len(),
        2
    );
}

// If the server restarts without sending the termination packets, will the client time out and
// reconnect?
#[test]
fn server_not_responding() {
    let (mut simulated_hardware, mut cores) =
        simulated_pair(LONGER_CLIENT_WIRE_CONFIG, LONGER_SERVER_WIRE_CONFIG, 0);

    simulated_hardware.make_outgoing_packet(&client_addr(), &[1, 4, 0, 5]);
    simulated_hardware.make_outgoing_packet(&server_addr(), &[5, 4, 0, 1]);
    simulated_hardware.run_until(&mut cores, ms(500.0));
    // ensure that they are actually connected to prevent this test from falling out of date
    assert_eq!(
        simulated_hardware
            .sent_incoming_packets(&server_addr())
            .len(),
        1
    );
    assert_eq!(
        simulated_hardware
            .sent_incoming_packets(&client_addr())
            .len(),
        1
    );

    // replace the old server without properly terminating it
    let num_outgoing_packets_before_destruction = simulated_hardware
        .sent_outgoing_packets(&server_addr())
        .len();
    cores.remove(&server_addr());
    // ensure that it isn't somehow sending packets during destruction
    assert_eq!(
        num_outgoing_packets_before_destruction,
        simulated_hardware
            .sent_outgoing_packets(&server_addr())
            .len()
    );

    cores.insert(
        server_addr(),
        core::server::Core::new(
            core::server::Config {
                pre_shared_key: PSK.into(),
            },
            &mut simulated_hardware.hardware(server_addr()),
        )
        .unwrap()
        .into(),
    );

    simulated_hardware.run_until(&mut cores, ms(11_000.0));
    simulated_hardware.make_outgoing_packet(&client_addr(), &[1, 4, 0, 5]);
    simulated_hardware.make_outgoing_packet(&server_addr(), &[5, 4, 0, 1]);
    simulated_hardware.run_until(&mut cores, ms(11_500.0));
    assert_eq!(
        simulated_hardware
            .sent_incoming_packets(&server_addr())
            .len(),
        2
    );
    assert_eq!(
        simulated_hardware
            .sent_incoming_packets(&client_addr())
            .len(),
        2
    );
}

// If the client restarts without sending the termination packets, will the server time out and
// allow the client to reconnect?
#[test]
fn client_not_responding() {
    let (mut simulated_hardware, mut cores) =
        simulated_pair(LONGER_CLIENT_WIRE_CONFIG, LONGER_SERVER_WIRE_CONFIG, 0);

    simulated_hardware.make_outgoing_packet(&client_addr(), &[1, 4, 0, 5]);
    simulated_hardware.make_outgoing_packet(&server_addr(), &[5, 4, 0, 1]);
    simulated_hardware.run_until(&mut cores, ms(500.0));
    // ensure that they are actually connected to prevent this test from falling out of date
    assert_eq!(
        simulated_hardware
            .sent_incoming_packets(&server_addr())
            .len(),
        1
    );
    assert_eq!(
        simulated_hardware
            .sent_incoming_packets(&client_addr())
            .len(),
        1
    );

    // replace the old client without properly terminating it
    let num_outgoing_packets_before_destruction = simulated_hardware
        .sent_outgoing_packets(&client_addr())
        .len();
    cores.remove(&client_addr());
    // ensure that it isn't somehow sending packets during destruction
    assert_eq!(
        num_outgoing_packets_before_destruction,
        simulated_hardware
            .sent_outgoing_packets(&client_addr())
            .len()
    );

    cores.insert(
        client_addr(),
        core::client::Core::new(
            core::client::Config {
                pre_shared_key: PSK.into(),
                client_wire_config: LONGER_CLIENT_WIRE_CONFIG,
                server_wire_config: LONGER_SERVER_WIRE_CONFIG,
                peer_address: server_addr(),
            },
            &mut simulated_hardware.hardware(client_addr()),
        )
        .unwrap()
        .into(),
    );

    simulated_hardware.run_until(&mut cores, ms(11_000.0));
    simulated_hardware.make_outgoing_packet(&client_addr(), &[1, 4, 0, 5]);
    simulated_hardware.make_outgoing_packet(&server_addr(), &[5, 4, 0, 1]);
    simulated_hardware.run_until(&mut cores, ms(11_500.0));
    assert_eq!(
        simulated_hardware
            .sent_incoming_packets(&server_addr())
            .len(),
        2
    );
    assert_eq!(
        simulated_hardware
            .sent_incoming_packets(&client_addr())
            .len(),
        2
    );
}

// TODO more tests:
// + DTLS handshake from a client when another client already has an established connection
// + Packet finalization time (ie, submitted to hardware with the right buffer before they /need/ to be sent)
// + SSL Alerts
// + Differing protocol versions
// + Deserialization failures
