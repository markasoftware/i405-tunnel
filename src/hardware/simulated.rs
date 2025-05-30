use std::cmp::min;
use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;

use crate::array_array::IpPacketBuffer;
use crate::core::Core;
use crate::{core, hardware::Hardware};

#[derive(Debug, Eq, PartialEq, Clone)]
struct OneSideInfo {
    addr: SocketAddr,

    /// Packets already sent out by the side
    // At some point we may not want this to be a LogicalIpPacket and instead include more information
    sent_outgoing_packets: Vec<WanPacket>,
    /// Packets to be read by this side, along with the time they'll become available.
    unread_outgoing_packets: VecDeque<IpPacketBuffer>,

    unread_incoming_packets: VecDeque<WanPacket>,
    sent_incoming_packets: Vec<LocalPacket>,

    /// For each outgoing packet that's been read by the core, what timestamp was it read at?
    outgoing_read_times: Vec<u64>,
    // The next time we should wake up this thread.
    timer: Option<u64>,
    next_read_outgoing: MaybeTime,
}

impl OneSideInfo {
    fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            sent_outgoing_packets: Vec::new(),
            unread_outgoing_packets: VecDeque::new(),
            unread_incoming_packets: VecDeque::new(),
            sent_incoming_packets: Vec::new(),
            outgoing_read_times: Vec::new(),
            timer: None,
            next_read_outgoing: MaybeTime::None,
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
struct WanPacket {
    buffer: IpPacketBuffer,
    source: SocketAddr,
    dest: SocketAddr,
    timestamp: u64,
}

#[derive(Debug, Eq, PartialEq, Clone)]
struct LocalPacket {
    buffer: IpPacketBuffer,
    timestamp: u64,
}

#[derive(Debug, Eq, PartialEq, Clone)]
enum MaybeTime {
    Scheduled(u64),
    Immediate,
    None,
}

/// Hardware implementation for testing only.
#[derive(Debug)]
pub(crate) struct SimulatedHardware {
    peers: BTreeMap<SocketAddr, OneSideInfo>,
    /// All packets that have been sent from any of the sides are collected here in addition to the
    /// specific peers they were sent from/to.
    all_wan_packets: Vec<WanPacket>,
    timestamp: u64,
}

impl SimulatedHardware {
    fn new(peer_addrs: Vec<SocketAddr>) -> Self {
        Self {
            peers: BTreeMap::from_iter(
                peer_addrs
                    .into_iter()
                    .map(|addr| (addr, OneSideInfo::new(addr))),
            ),
            all_wan_packets: Vec::new(),
            timestamp: 0,
        }
    }

    fn hardware<'a>(&'a mut self, addr: SocketAddr) -> OneSideHardware<'a> {
        OneSideHardware {
            simulated: self,
            our_addr: addr,
        }
    }

    /// Read as "run until, but not including, stop_timestamp." Upon exit, the timestamp field will
    /// be equal to stop_timestamp, but no events at that timestamp will have been processed.
    fn run_until(
        &mut self,
        cores: &mut BTreeMap<SocketAddr, core::ConcreteCore>,
        stop_timestamp: u64,
    ) {
        'main_loop: while self.timestamp < stop_timestamp {
            let timestamp = self.timestamp;
            let mut next_event_timestamp = stop_timestamp;

            // first, check if any side has immediate tasks to perform
            // have to collect so we don't borrow self.peers
            for addr in self.peers.keys().cloned().collect::<Vec<SocketAddr>>() {
                let peer = self.peers.get_mut(&addr).unwrap();
                let core = cores
                    .get_mut(&addr)
                    .expect("Missing addr from cores argument to run_until");

                // timer
                if let Some(timer) = peer.timer {
                    assert!(
                        timer >= timestamp,
                        "We slept past a timer? Or maybe timer was set in the past? Timer {} vs timestamp {}",
                        timer,
                        timestamp
                    );
                    if timer == timestamp {
                        core.on_timer(&mut self.hardware(addr), timestamp);
                        // the continue serves two purposes: (1) ensure that if handling one event
                        // causes other events to happen at the same timestamp, we don't advance the
                        // timestamp and (2) help the borrow checker by letting it discard our other
                        // mutable borrows of self before calling on_timer, enabling reborrowing.
                        continue 'main_loop;
                    } else {
                        next_event_timestamp = min(next_event_timestamp, timer);
                    }
                }

                // scheduled read outgoing
                match peer.next_read_outgoing {
                    MaybeTime::Scheduled(scheduled_time) => {
                        // it's acceptable for scheduled_time to be in the past because it might
                        // have been scheduled in the past but no packets were available yet
                        if scheduled_time <= timestamp {
                            if let Some(outgoing_packet) = peer.unread_outgoing_packets.pop_front()
                            {
                                core.on_read_outgoing_packet(
                                    &mut self.hardware(addr),
                                    &outgoing_packet,
                                    timestamp,
                                );
                                continue 'main_loop;
                            }
                        } else {
                            next_event_timestamp = min(next_event_timestamp, scheduled_time);
                        }
                    }
                    MaybeTime::Immediate => {
                        // this is copy pasted from above, maybe should dedupe
                        if let Some(outgoing_packet) = peer.unread_outgoing_packets.pop_front() {
                            core.on_read_outgoing_packet(
                                &mut self.hardware(addr),
                                &outgoing_packet,
                                timestamp,
                            );
                            continue 'main_loop;
                        }
                    }
                    MaybeTime::None => (),
                }

                // read incoming
                if let Some(incoming_packet) = peer.unread_incoming_packets.pop_front() {
                    assert_eq!(incoming_packet.dest, addr);
                    core.on_read_incoming_packet(
                        &mut self.hardware(addr),
                        &incoming_packet.buffer,
                        incoming_packet.source,
                    );
                    continue 'main_loop;
                }
            }

            // If there's nothing to do immediately, then wait until the next time we'll be able to do something!
            self.timestamp = next_event_timestamp;
        }
    }
}

struct OneSideHardware<'a> {
    simulated: &'a mut SimulatedHardware,
    our_addr: SocketAddr,
}

impl<'a> OneSideHardware<'a> {
    fn our_side(&mut self) -> &mut OneSideInfo {
        self.simulated.peers.get_mut(&self.our_addr).unwrap()
    }
}

impl<'a> Hardware for OneSideHardware<'a> {
    fn set_timer(&mut self, timestamp: u64) -> Option<u64> {
        std::mem::replace(&mut self.our_side().timer, Some(timestamp))
    }

    fn timestamp(&self) -> u64 {
        self.simulated.timestamp.clone()
    }

    fn read_outgoing_packet(&mut self, no_earlier_than: Option<u64>) {
        self.our_side().next_read_outgoing = match no_earlier_than {
            Some(no_earlier_than) => MaybeTime::Scheduled(no_earlier_than),
            None => MaybeTime::Immediate,
        }
    }

    fn send_outgoing_packet(
        &mut self,
        packet: &[u8],
        destination: SocketAddr,
        timestamp: Option<u64>,
    ) -> super::Result<()> {
        // temporary restriction?
        assert!(
            self.our_side()
                .sent_outgoing_packets
                .last()
                .is_none_or(|last| timestamp.is_none_or(|ts| last.timestamp <= ts)),
            "Sent outgoing packets must be in ascending timestamp order"
        );

        let actual_timestamp = timestamp.unwrap_or(self.timestamp());
        let wan_packet = WanPacket {
            buffer: IpPacketBuffer::new(packet),
            timestamp: actual_timestamp,
            source: self.our_addr,
            dest: destination,
        };

        self.our_side()
            .sent_outgoing_packets
            .push(wan_packet.clone());
        self.simulated.all_wan_packets.push(wan_packet.clone());
        if let Some(destination_peer) = self.simulated.peers.get_mut(&destination) {
            destination_peer
                .unread_incoming_packets
                .push_back(wan_packet);
        }

        Ok(())
    }

    fn send_incoming_packet(&mut self, packet: &[u8], timestamp: Option<u64>) -> super::Result<()> {
        assert!(
            self.our_side()
                .sent_incoming_packets
                .last()
                .is_none_or(|last| timestamp.is_none_or(|ts| last.timestamp <= ts)),
            "Sent incoming packets must be in ascending timestamp order"
        );

        let actual_timestamp = timestamp.unwrap_or(self.timestamp());
        self.our_side().sent_incoming_packets.push(LocalPacket {
            buffer: IpPacketBuffer::new(packet),
            timestamp: actual_timestamp,
        });
        Ok(())
    }

    fn socket_connect(&mut self, _socket_addr: &SocketAddr) -> super::Result<()> {
        unimplemented!("TODO");
    }

    // TODO rethink this fn more generally: Should it perhaps be part of clear_event_listeners?
    fn socket_disconnect(&mut self) -> super::Result<()> {
        unimplemented!("TODO");
    }

    fn clear_event_listeners(&mut self) {
        self.our_side().timer = None;
        self.our_side().next_read_outgoing = MaybeTime::None;
    }
}
