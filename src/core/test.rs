/// The bulk of "integration"-style tests go here. We use a "simulated" Hardware so everything's
/// super fast and reproducible. We also have some true integration tests that set up Linux network
/// netspaces and crap, but it's much easier to mess with stuff and assert stuff here.
use crate::array_array::IpPacketBuffer;
use crate::constants::DTLS_HEADER_LENGTH;
use crate::core;
use crate::hardware::simulated::{LocalPacket, SimulatedHardware};

use std::collections::BTreeMap;
use std::net::SocketAddr;

const PSK: &[u8] = b"password";

fn client_addr() -> SocketAddr {
    "10.140.5.1:1405".parse().unwrap()
}

fn server_addr() -> SocketAddr {
    "10.140.5.2:1405".parse().unwrap()
}

fn simulated_pair(
    c2s_wire_config: core::WireConfig,
    s2c_wire_config: core::WireConfig,
) -> (SimulatedHardware, BTreeMap<SocketAddr, core::ConcreteCore>) {
    let mut simulated_hardware = SimulatedHardware::new(vec![client_addr(), server_addr()], 0);
    let server_core = core::server::Core::new(core::server::Config {
        pre_shared_key: PSK.into(),
    })
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

fn default_simulated_pair() -> (SimulatedHardware, BTreeMap<SocketAddr, core::ConcreteCore>) {
    simulated_pair(
        core::WireConfig {
            packet_length: DEFAULT_PACKET_LENGTH,
            packet_interval: 1423,
            packet_interval_offset: 0,
        },
        core::WireConfig {
            packet_length: DEFAULT_PACKET_LENGTH,
            packet_interval: 1411,
            packet_interval_offset: 0,
        },
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
    let (mut simulated_hardware, mut cores) = default_simulated_pair();

    simulated_hardware.make_outgoing_packet(&client_addr(), &[1, 4, 0, 5]);
    simulated_hardware.make_outgoing_packet(&server_addr(), &[4, 3, 2, 1]);
    // depending on the implementation, it can reasonably send the first packet before reading the
    // outgoing packet (in fact, that's what the current implementation does), so we need to wait
    // long enough that it can actually read the outgoing packet. This is long enough for two
    // packets.
    simulated_hardware.run_until(&mut cores, 3000);

    assert_eq!(
        simulated_hardware.incoming_packets(&client_addr()),
        &vec![LocalPacket {
            buffer: IpPacketBuffer::new(&[4, 3, 2, 1]),
            timestamp: 1411,
        }]
    );
    assert_eq!(
        simulated_hardware.incoming_packets(&server_addr()),
        &vec![LocalPacket {
            buffer: IpPacketBuffer::new(&[1, 4, 0, 5]),
            timestamp: 1423,
        }]
    );

    simulated_hardware.make_outgoing_packet(&client_addr(), &[7]);
    simulated_hardware.run_until(&mut cores, 4500);

    assert_eq!(simulated_hardware.incoming_packets(&server_addr()).len(), 2);
    assert_eq!(
        simulated_hardware.incoming_packets(&server_addr())[1],
        LocalPacket {
            buffer: IpPacketBuffer::new(&[7]),
            timestamp: 4269
        }
    );
}

#[test]
fn fragmentation() {
    setup_logging();
    let (mut simulated_hardware, mut cores) = default_simulated_pair();

    let packet = long_packet(1200);

    simulated_hardware.run_until(&mut cores, 1000);
    simulated_hardware.make_outgoing_packet(&server_addr(), &packet);
    simulated_hardware.run_until(&mut cores, 2000);
    assert!(
        simulated_hardware
            .incoming_packets(&client_addr())
            .is_empty()
    );
    simulated_hardware.run_until(&mut cores, 3000);
    assert_eq!(
        simulated_hardware.incoming_packets(&client_addr()),
        &vec![LocalPacket {
            buffer: packet,
            timestamp: 2822,
        }]
    );
}

/// Test that packets over the WAN are actually the correct size
#[test]
fn wan_packet_length() {
    setup_logging();
    let (mut simulated_hardware, mut cores) = default_simulated_pair();

    let wan_packet_length: usize = DTLS_HEADER_LENGTH
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

    simulated_hardware.run_until(&mut cores, 2000);
    let empty_packets = simulated_hardware.all_wan_packets();
    let num_empty_packets = empty_packets.len();
    // just so this test doesn't get stale if others change
    assert_eq!(num_handshake_packets + 2, num_empty_packets);
    // make sure actual data packets
    assert_eq!(
        empty_packets[empty_packets.len() - 1].buffer.len(),
        wan_packet_length
    );
    assert_eq!(
        empty_packets[empty_packets.len() - 2].buffer.len(),
        wan_packet_length
    );

    // now send an actual, large packet and make sure the size is the same
    simulated_hardware.make_outgoing_packet(&client_addr(), &long_packet(1200));
    simulated_hardware.run_until(&mut cores, 3000);
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

    let (mut simulated_hardware, mut cores) = default_simulated_pair();
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
    simulated_hardware.run_until(&mut cores, 2000);
    assert_eq!(
        simulated_hardware.all_wan_packets().len(),
        num_handshake_wan_packets.checked_add(2).unwrap()
    );
    // we'll verify the actual contents later
    assert_eq!(simulated_hardware.incoming_packets(&server_addr()).len(), 2);

    // now test that it /doesn't/ work when we make it one larger
    simulated_hardware.make_outgoing_packet(&client_addr(), &long_packet(first_message_length));
    simulated_hardware.make_outgoing_packet(
        &client_addr(),
        &long_packet(second_message_length.checked_add(1).unwrap()),
    );
    simulated_hardware.run_until(&mut cores, 4000);
    // just fud because I don't fully trust the SimulatedHardware yet
    assert_eq!(simulated_hardware.incoming_packets(&server_addr()).len(), 3);
    simulated_hardware.run_until(&mut cores, 5000);

    assert_eq!(
        simulated_hardware.incoming_packets(&server_addr()),
        &vec![
            LocalPacket {
                buffer: long_packet(first_message_length),
                timestamp: 1423,
            },
            LocalPacket {
                buffer: long_packet(second_message_length),
                timestamp: 1423,
            },
            LocalPacket {
                buffer: long_packet(first_message_length),
                timestamp: 2846,
            },
            LocalPacket {
                buffer: long_packet(second_message_length + 1),
                timestamp: 4269,
            },
        ]
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
