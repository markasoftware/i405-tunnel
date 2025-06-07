/// The bulk of "integration"-style tests go here. We use a "simulated" Hardware so everything's
/// super fast and reproducible. We also have some true integration tests that set up Linux network
/// netspaces and crap, but it's much easier to mess with stuff and assert stuff here.
use crate::array_array::IpPacketBuffer;
use crate::constants::DTLS_HEADER_LENGTH;
use crate::core;
use crate::hardware::simulated::{LocalPacket, SimulatedHardware};
use crate::wire_config::WireConfig;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::Duration;

use test_case::test_matrix;

const PSK: &[u8] = b"password";
const DEFAULT_C2S_WIRE_CONFIG: WireConfig = WireConfig {
    packet_length: DEFAULT_PACKET_LENGTH,
    packet_interval: 1_423_000, // 1.423ms
    packet_interval_offset: 0,
};
const DEFAULT_S2C_WIRE_CONFIG: WireConfig = WireConfig {
    packet_length: DEFAULT_PACKET_LENGTH,
    packet_interval: 1_411_000, // 1.411ms
    packet_interval_offset: 0,
};
const LONGER_C2S_WIRE_CONFIG: WireConfig = WireConfig {
    packet_length: DEFAULT_PACKET_LENGTH,
    packet_interval: 142_300_000, // 142.3ms
    packet_interval_offset: 0,
};
const LONGER_S2C_WIRE_CONFIG: WireConfig = WireConfig {
    packet_length: DEFAULT_PACKET_LENGTH,
    packet_interval: 141_100_000, // 141.1ms
    packet_interval_offset: 0,
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
    c2s_wire_config: WireConfig,
    s2c_wire_config: WireConfig,
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
            c2s_wire_config,
            s2c_wire_config,
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

const DEFAULT_PACKET_LENGTH: u16 = 1000;

fn default_simulated_pair(
    default_delay: u64,
) -> (SimulatedHardware, BTreeMap<SocketAddr, core::ConcreteCore>) {
    simulated_pair(
        DEFAULT_C2S_WIRE_CONFIG,
        DEFAULT_S2C_WIRE_CONFIG,
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

    simulated_hardware.make_outgoing_packet(&client_addr(), &[1, 4, 0, 5]);
    simulated_hardware.make_outgoing_packet(&server_addr(), &[4, 3, 2, 1]);
    // at 1.411ms, the server hasn't yet gotten the first "normal" packet from the client, so it's
    // not going to send anything outgoing until 2.822.
    simulated_hardware.run_until(&mut cores, ms(3.0));

    assert_eq!(
        simulated_hardware.incoming_packets(&client_addr()),
        &vec![LocalPacket {
            buffer: IpPacketBuffer::new(&[4, 3, 2, 1]),
            timestamp: ms(1.411 * 2.0),
        }]
    );
    assert_eq!(
        simulated_hardware.incoming_packets(&server_addr()),
        &vec![LocalPacket {
            buffer: IpPacketBuffer::new(&[1, 4, 0, 5]),
            timestamp: ms(1.423),
        }]
    );

    simulated_hardware.make_outgoing_packet(&client_addr(), &[7]);
    simulated_hardware.run_until(&mut cores, ms(4.5));

    assert_eq!(simulated_hardware.incoming_packets(&server_addr()).len(), 2);
    assert_eq!(
        simulated_hardware.incoming_packets(&server_addr())[1],
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
            .incoming_packets(&client_addr())
            .is_empty()
    );
    simulated_hardware.run_until(&mut cores, ms(4.5));
    assert_eq!(
        simulated_hardware.incoming_packets(&client_addr()),
        &vec![LocalPacket {
            buffer: packet,
            timestamp: ms(1.411 * 3.0),
        }]
    );
}

/// Test that packets over the WAN are actually the correct size
#[test]
fn wan_packet_length() {
    setup_logging();
    let (mut simulated_hardware, mut cores) = default_simulated_pair(0);

    let wan_packet_length: usize = usize::from(DTLS_HEADER_LENGTH)
        .checked_add(DEFAULT_PACKET_LENGTH.into())
        .unwrap();

    simulated_hardware.run_until(&mut cores, 1);
    let handshake = simulated_hardware.all_wan_packets();
    let num_handshake_packets = handshake.len();
    // for sanity, check that the first packet is smaller than we requested, because it should just
    // be a ClientHello.
    assert!(handshake[0].buffer.len() < wan_packet_length);
    // the last two should be handshakes, and of the correct size
    assert_eq!(
        handshake[handshake.len() - 1].buffer.len(),
        wan_packet_length
    );
    assert_eq!(
        handshake[handshake.len() - 2].buffer.len(),
        wan_packet_length
    );

    simulated_hardware.run_until(&mut cores, ms(3.0));
    let empty_packets = simulated_hardware.all_wan_packets();
    let num_empty_packets = empty_packets.len();
    // just so this test doesn't get stale if others change
    assert_eq!(num_handshake_packets + 3, num_empty_packets);
    // make sure actual data packets
    assert_eq!(
        empty_packets[empty_packets.len() - 1].buffer.len(),
        wan_packet_length
    );
    assert_eq!(
        empty_packets[empty_packets.len() - 2].buffer.len(),
        wan_packet_length
    );
    assert_eq!(
        empty_packets[empty_packets.len() - 3].buffer.len(),
        wan_packet_length
    );

    // now send an actual, large packet and make sure the size is the same
    simulated_hardware.make_outgoing_packet(&client_addr(), &long_packet(1200));
    simulated_hardware.run_until(&mut cores, ms(4.5));
    let full_packets = simulated_hardware.all_wan_packets();
    assert_eq!(num_empty_packets + 2, full_packets.len());
    assert_eq!(
        full_packets[full_packets.len() - 1].buffer.len(),
        wan_packet_length
    );
    assert_eq!(
        full_packets[full_packets.len() - 2].buffer.len(),
        wan_packet_length
    );
}

/// Test that we can pack multiple packets into the same network packet when they fit.
#[test]
fn packing() {
    setup_logging();

    // type byte and length only
    const MESSAGE_HEADER_LENGTH: usize = 1 + 2;
    // I really need to stop doing the checked arithmetic, don't I?
    let first_message_length: usize = usize::from(DEFAULT_PACKET_LENGTH).checked_div(2).unwrap();
    let second_message_length: usize = usize::from(DEFAULT_PACKET_LENGTH)
        .checked_sub(MESSAGE_HEADER_LENGTH.checked_mul(2).unwrap())
        .unwrap()
        .checked_sub(first_message_length)
        .unwrap();

    let (mut simulated_hardware, mut cores) = default_simulated_pair(0);
    simulated_hardware.make_outgoing_packet(&client_addr(), &long_packet(first_message_length));
    simulated_hardware.make_outgoing_packet(&client_addr(), &long_packet(second_message_length));

    simulated_hardware.run_until(&mut cores, 1);
    assert!(
        simulated_hardware
            .incoming_packets(&server_addr())
            .is_empty()
    );
    // this is just FUD to make sure it somehow doesn't send multiple packets TODO consider adding
    // some global thing so if in /any/ of our tests it sends packets when it shouldn't, or of the
    // wrong size, it errors out, rather than needing to check on a test-by-test basis.
    let num_handshake_wan_packets = simulated_hardware.all_wan_packets().len();
    simulated_hardware.run_until(&mut cores, ms(3.0));
    assert_eq!(
        simulated_hardware.all_wan_packets().len(),
        num_handshake_wan_packets.checked_add(3).unwrap()
    );
    // we'll verify the actual contents later
    assert_eq!(simulated_hardware.incoming_packets(&server_addr()).len(), 2);

    // now test that it /doesn't/ work when we make it one larger
    simulated_hardware.make_outgoing_packet(&client_addr(), &long_packet(first_message_length));
    simulated_hardware.make_outgoing_packet(
        &client_addr(),
        &long_packet(second_message_length.checked_add(1).unwrap()),
    );
    simulated_hardware.run_until(&mut cores, ms(5.0));
    // just fud because I don't fully trust the SimulatedHardware yet
    assert_eq!(simulated_hardware.incoming_packets(&server_addr()).len(), 3);
    simulated_hardware.run_until(&mut cores, ms(6.0));

    assert_eq!(
        simulated_hardware.incoming_packets(&server_addr()),
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
            c2s_wire_config: DEFAULT_C2S_WIRE_CONFIG,
            s2c_wire_config: DEFAULT_S2C_WIRE_CONFIG,
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
            .incoming_packets(&client_addr())
            .is_empty()
    );
    assert!(
        simulated_hardware
            .incoming_packets(&server_addr())
            .is_empty()
    );

    std::thread::sleep(Duration::from_millis(1010));
    simulated_hardware.run_until(&mut cores, ms(6000.0));
    let client_incoming_packets = simulated_hardware.incoming_packets(&client_addr());
    let server_incoming_packets = simulated_hardware.incoming_packets(&server_addr());
    assert_eq!(client_incoming_packets.len(), 1);
    assert_eq!(server_incoming_packets.len(), 1);
    assert_eq!(&client_incoming_packets[0].buffer[..], &[4, 3, 2, 1]);
    assert_eq!(&server_incoming_packets[0].buffer[..], &[1, 4, 0, 5]);
}

// Test to ensure that we can handle a handshake packet in established mode
// TODO add another argument so we delay one packet, and drop another once https://github.com/wolfSSL/wolfssl/issues/8855 is fixed
// TODO test drops not just reorders, weird problems occur
#[test_matrix(0..20)]
#[ignore]
#[cfg(FALSE)]
fn long_distance_reorder(which_packet_reorder: u64) {
    #[cfg(feature = "wolfssl-debug")]
    wolfssl::enable_debugging(true);

    setup_logging();
    // TODO factor out the hardware and core creation into something where we can pass in a lambda doing delays
    let mut simulated_hardware =
        SimulatedHardware::new(vec![client_addr(), server_addr()], ms(1.0));
    simulated_hardware.delay_packet(which_packet_reorder, ms(2000.0));
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
            c2s_wire_config: LONGER_C2S_WIRE_CONFIG,
            s2c_wire_config: LONGER_S2C_WIRE_CONFIG,
        },
        &mut simulated_hardware.hardware(client_addr()),
    )
    .unwrap();
    let mut cores = BTreeMap::from([
        (client_addr(), client_core.into()),
        (server_addr(), server_core.into()),
    ]);

    simulated_hardware.run_until(&mut cores, ms(1500.0));
    std::thread::sleep(Duration::from_millis(1010));
    simulated_hardware.run_until(&mut cores, ms(4000.0));
    // send a packet to ensure we are actually in established mode
    simulated_hardware.make_outgoing_packet(&client_addr(), &[1, 4, 0, 5]);
    simulated_hardware.run_until(&mut cores, ms(5000.0));
    assert_eq!(simulated_hardware.incoming_packets(&server_addr()).len(), 1);
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
            c2s_wire_config: DEFAULT_C2S_WIRE_CONFIG,
            s2c_wire_config: DEFAULT_S2C_WIRE_CONFIG,
        },
        &mut simulated_hardware.hardware(evil_client_addr),
    )
    .unwrap();
    let noop_core = core::noop::Core::new(&mut simulated_hardware.hardware(good_client_addr));
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
            c2s_wire_config: DEFAULT_C2S_WIRE_CONFIG,
            s2c_wire_config: DEFAULT_S2C_WIRE_CONFIG,
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
        simulated_hardware.incoming_packets(&good_client_addr).len(),
        1
    );
    assert!(
        simulated_hardware
            .incoming_packets(&evil_client_addr)
            .is_empty()
    );
}

// TODO more tests:
// + Multiple clients doing DTLS handshakes simultaneously, whoever finishes first gets the prize
// + DTLS handshake from a client when another client already has an established connection
// + Packet drops and timeouts, esp. during in-protocol handshake (could theoretically abstract the in-protocol handshake even more in order to make it more openssl-like and then test it more isolated-ly, but it's simpler not to for now)
// + Packet finalization time (ie, submitted to hardware with the right buffer before they /need/ to be sent)
// + SSL Alerts
// + Packet retransmissions and reorderings, esp. between stages of the state machine. Specifically:
//   - DTLS handshake messages during in-protocol and established, and in-protocol handshake messages during established.
//   - After server disconnect/reconnect, messages from the previous connection. These should fail DTLS decryption.
//   - C2S post-handshake messages arriving before handshake (shouldn't actually crash it)
// + Server disconnecting and reconnecting to a new client.
// + Differing protocol versions
// + Deserialization failures
