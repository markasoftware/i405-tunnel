use crate::array_array::IpPacketBuffer;
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

fn setup_logging() {
    // this is a bit hacky because it initializes it for other tests that may run after ours, even
    // if it causes undue overhead. But logging shouldn't ever be that slow anyway.
    let _ = env_logger::builder().is_test(true).try_init();
}

/// Test a simple connection (which, to be honest, still isn't very simple): DTLS handshake, I405
/// handshake, and then a few packets each way.
#[test]
fn test_simple() {
    setup_logging();
    let (mut simulated_hardware, mut cores) = simulated_pair(
        core::WireConfig {
            packet_length: 1000,
            packet_interval: 1423,
            packet_interval_offset: 0,
        },
        core::WireConfig {
            packet_length: 1000,
            packet_interval: 1411,
            packet_interval_offset: 0,
        },
    );

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
fn test_fragmentation() {
    setup_logging();
    let (mut simulated_hardware, mut cores) = simulated_pair(
        core::WireConfig {
            packet_length: 1000,
            packet_interval: 1423,
            packet_interval_offset: 0,
        },
        core::WireConfig {
            packet_length: 1000,
            packet_interval: 1411,
            packet_interval_offset: 0,
        },
    );

    let mut packet_vec = Vec::new();
    for i in 0u32..1200 {
        packet_vec.push((i % u32::from(u8::MAX)).try_into().unwrap());
    }
    let packet = IpPacketBuffer::new(&packet_vec);

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
