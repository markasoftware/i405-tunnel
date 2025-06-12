use std::cmp::min;
use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet, VecDeque};
use std::net::SocketAddr;

use anyhow::Result;

use crate::array_array::IpPacketBuffer;
use crate::constants::MAX_IP_PACKET_LENGTH;
use crate::core::Core;
use crate::{core, hardware::Hardware};

#[derive(Debug, Clone)]
struct OneSideInfo {
    addr: SocketAddr,

    /// Packets already sent out by the side
    // At some point we may not want this to be a LogicalIpPacket and instead include more information
    sent_outgoing_packets: Vec<WanPacket>,
    /// Packets to be read by this side, along with the time they'll become available.
    unread_outgoing_packets: VecDeque<IpPacketBuffer>,

    unread_incoming_packets: BinaryHeap<WanPacket>,
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
            unread_incoming_packets: BinaryHeap::new(),
            sent_incoming_packets: Vec::new(),
            outgoing_read_times: Vec::new(),
            timer: None,
            next_read_outgoing: MaybeTime::None,
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub(crate) struct WanPacket {
    pub(crate) buffer: IpPacketBuffer,
    pub(crate) source: SocketAddr,
    pub(crate) dest: SocketAddr,
    pub(crate) receipt_timestamp: u64,
}

// Ord and PartialOrd for WanPacket are reversed so that we can use it in BinaryHeaps to get the
// "next" WanPacket.
impl Ord for WanPacket {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.receipt_timestamp
            .cmp(&other.receipt_timestamp)
            .reverse()
    }
}

impl PartialOrd for WanPacket {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(&other))
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub(crate) struct LocalPacket {
    pub(crate) buffer: IpPacketBuffer,
    pub(crate) timestamp: u64,
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
    packet_counter: u64,
    packets_to_drop: HashSet<u64>,
    /// Additional delay beyond the `default_delay`
    packets_to_delay: HashMap<u64, u64>,
    default_delay: u64,
    timestamp: u64,
}

impl SimulatedHardware {
    pub(crate) fn new(peer_addrs: Vec<SocketAddr>, default_delay: u64) -> Self {
        Self {
            peers: BTreeMap::from_iter(
                peer_addrs
                    .into_iter()
                    .map(|addr| (addr, OneSideInfo::new(addr))),
            ),
            all_wan_packets: Vec::new(),
            packet_counter: 0,
            packets_to_drop: HashSet::new(),
            packets_to_delay: HashMap::new(),
            default_delay,
            timestamp: 0,
        }
    }

    pub(crate) fn hardware<'a>(&'a mut self, addr: SocketAddr) -> OneSideHardware<'a> {
        OneSideHardware {
            simulated: self,
            our_addr: addr,
        }
    }

    pub(crate) fn make_outgoing_packet(&mut self, addr: &SocketAddr, packet: &[u8]) {
        self.peers
            .get_mut(addr)
            .expect("Non-existent `addr` to make_outgoing_packet")
            .unread_outgoing_packets
            .push_back(IpPacketBuffer::new(packet));
    }

    pub(crate) fn incoming_packets(&self, addr: &SocketAddr) -> &Vec<LocalPacket> {
        &self.peers[addr].sent_incoming_packets
    }

    pub(crate) fn all_wan_packets(&self) -> &Vec<WanPacket> {
        &self.all_wan_packets
    }

    pub(crate) fn drop_packet(&mut self, nth: u64) {
        let counter_to_drop = self.packet_counter.checked_add(nth).unwrap();
        assert!(
            !self.packets_to_drop.contains(&counter_to_drop),
            "Already were gonna drop packet {} (nth: {})",
            counter_to_drop,
            nth
        );
        self.packets_to_drop.insert(counter_to_drop);
    }

    pub(crate) fn delay_packet(&mut self, nth: u64, duration: u64) {
        let counter_to_delay = self.packet_counter.checked_add(nth).unwrap();
        assert!(
            !self.packets_to_delay.contains_key(&counter_to_delay),
            "Already were gonna delay packet {} (nth: {})",
            counter_to_delay,
            nth
        );
        assert!(
            !self.packets_to_drop.contains(&counter_to_delay),
            "Can't delay packet we're gonna drop {} (nth: {})",
            counter_to_delay,
            nth
        );
        self.packets_to_delay.insert(counter_to_delay, duration);
    }

    /// Read as "run until, but not including, stop_timestamp." Upon exit, the timestamp field will
    /// be equal to stop_timestamp, but no events at that timestamp will have been processed.
    pub(crate) fn run_until(
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
                        self.debug(format!("Timer triggered for {} at {}ns", addr, timestamp));
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
                                self.debug(format!(
                                    "Reading outgoing packet on {} at {}ns",
                                    addr, timestamp
                                ));
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
                            self.debug(format!(
                                "Reading outgoing packet on {} at {}ns",
                                addr, timestamp
                            ));
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
                if let Some(incoming_packet) = peer.unread_incoming_packets.peek() {
                    if timestamp >= incoming_packet.receipt_timestamp {
                        let incoming_packet = peer.unread_incoming_packets.pop().unwrap();
                        self.debug(format!(
                            "Reading incoming packet of size {} on {}, from {}, at {}ns",
                            incoming_packet.buffer.len(),
                            addr,
                            incoming_packet.source,
                            timestamp
                        ));
                        assert_eq!(
                            incoming_packet.receipt_timestamp, timestamp,
                            "AFAIK no way for us to miss the receipt timestamp in simulation"
                        );
                        assert_eq!(incoming_packet.dest, addr);
                        core.on_read_incoming_packet(
                            &mut self.hardware(addr),
                            &incoming_packet.buffer,
                            incoming_packet.source,
                        );
                        continue 'main_loop;
                    } else {
                        next_event_timestamp =
                            min(next_event_timestamp, incoming_packet.receipt_timestamp);
                    }
                }
            }

            // If there's nothing to do immediately, then wait until the next time we'll be able to do something!
            self.debug(format!(
                "No action to do at current timestamp {}ns; advancing to {}ns",
                timestamp, next_event_timestamp
            ));
            self.timestamp = next_event_timestamp;
        }
    }

    // idk if AsRef<str> is really the best signature here
    fn debug<S: AsRef<str>>(&self, msg: S) {
        log::debug!("{}ns: {}", self.timestamp, msg.as_ref());
    }
}

pub(crate) struct OneSideHardware<'a> {
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
        let old_timestamp = std::mem::replace(&mut self.our_side().timer, Some(timestamp));
        self.simulated.debug(format!(
            "Setting timer for {} to {}ns (used to be {:?})",
            self.our_addr, timestamp, old_timestamp
        ));
        old_timestamp
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
    ) -> Result<()> {
        let packet_counter = self.simulated.packet_counter;
        self.simulated.packet_counter += 1;

        let sent_timestamp = timestamp.unwrap_or(self.timestamp());

        if self.simulated.packets_to_drop.contains(&packet_counter) {
            self.simulated.debug(format!(
                "Dropping packet from {} to {} of size {} (sent at {}ns)",
                self.our_addr,
                destination,
                packet.len(),
                sent_timestamp
            ));
            return Ok(());
        }

        let delay = self
            .simulated
            .default_delay
            .checked_add(
                self.simulated
                    .packets_to_delay
                    .get(&packet_counter)
                    .unwrap_or(&0)
                    .clone(),
            )
            .unwrap();
        let receipt_timestamp = sent_timestamp.checked_add(delay).unwrap();
        self.simulated.debug(format!(
            "Sending packet from {} to {} of size {} at {}ns (delay {}ns, to be received at {}ns)",
            self.our_addr,
            destination,
            packet.len(),
            sent_timestamp,
            delay,
            receipt_timestamp,
        ));
        let wan_packet = WanPacket {
            buffer: IpPacketBuffer::new(packet),
            receipt_timestamp,
            source: self.our_addr,
            dest: destination,
        };

        self.our_side()
            .sent_outgoing_packets
            .push(wan_packet.clone());
        self.simulated.all_wan_packets.push(wan_packet.clone());
        if let Some(destination_peer) = self.simulated.peers.get_mut(&destination) {
            destination_peer.unread_incoming_packets.push(wan_packet);
        }

        Ok(())
    }

    fn send_incoming_packet(&mut self, packet: &[u8], timestamp: Option<u64>) -> Result<()> {
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

    fn socket_connect(&mut self, _socket_addr: &SocketAddr) -> Result<()> {
        unimplemented!("TODO");
    }

    // TODO rethink this fn more generally: Should it perhaps be part of clear_event_listeners?
    fn socket_disconnect(&mut self) -> Result<()> {
        unimplemented!("TODO");
    }

    fn clear_event_listeners(&mut self) {
        self.our_side().timer = None;
        self.our_side().next_read_outgoing = MaybeTime::None;
    }

    fn mtu(&self, _peer: SocketAddr) -> Result<u16> {
        Ok(MAX_IP_PACKET_LENGTH.try_into().unwrap())
    }
}
