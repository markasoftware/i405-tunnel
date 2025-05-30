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
    let mut simulated_hardware = SimulatedHardware::new(vec![client_addr(), server_addr()]);
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

/// a packet of length 1200
fn packet_1200() -> IpPacketBuffer {
    let mut packet_vec = Vec::new();
    for i in 0u32..1200 {
        packet_vec.push((i % u32::from(u8::MAX)).try_into().unwrap());
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

    let packet = packet_1200();

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
fn wan_packet_size() {
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
    simulated_hardware.make_outgoing_packet(&client_addr(), &packet_1200());
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
    // TODO
}
