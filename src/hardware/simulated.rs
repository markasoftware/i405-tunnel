use std::cell::{Cell, RefCell};
use std::cmp::min;
use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet, VecDeque};
use std::net::SocketAddr;

use anyhow::Result;

use crate::array_array::IpPacketBuffer;
use crate::constants::MAX_IP_PACKET_LENGTH;
use crate::core::Core;
use crate::utils::RelativeDirection;
use crate::{core, hardware::Hardware};

use super::real::QdiscSettings;
use super::{ReadIncomingPacket, ReadOutgoingPacket, ShutdownRequested};

#[derive(Debug, Clone)]
struct OneSideInfo {
    addr: SocketAddr,
    // if socket_connect has been called, then only accept incoming packets from this address
    connected_addr: Cell<Option<SocketAddr>>,
    qdisc_settings: Cell<Option<QdiscSettings>>,

    /// Packets already sent out by the side. A little bit cursed because it's in the order that
    /// send_outgoing_packet is called, rather than by send_timestamp, so it's possible for
    /// send_timestamps to not be in ascending order here.
    sent_outgoing_packets: RefCell<Vec<WanPacket>>,
    /// Packets to be read by this side, along with the time they'll become available (last part not
    /// impl'd yet).
    unread_outgoing_packets: RefCell<VecDeque<IpPacketBuffer>>,
    /// set to true whenever a packet is added to unread_outgoing_packets from empty, which will
    /// cause on_event to be called immediately on next run_until (at which point this will be reset
    /// to false).
    has_unnotified_unread_outgoing_packets: Cell<bool>,

    unread_incoming_packets: RefCell<BinaryHeap<WanPacket>>,
    sent_incoming_packets: RefCell<Vec<LocalPacket>>,

    /// For each outgoing packet that's been read by the core, what timestamp was it read at?
    outgoing_read_times: RefCell<Vec<u64>>,

    /// Packet statuses registered by this peer
    packet_statuses: RefCell<Vec<PacketStatus>>,

    // The next time we should wake up this thread.
    timer: Cell<Option<u64>>,

    shutdown_requested: ShutdownRequested,
}

impl OneSideInfo {
    fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            connected_addr: Cell::new(None),
            qdisc_settings: Cell::new(None),
            sent_outgoing_packets: RefCell::new(Vec::new()),
            unread_outgoing_packets: RefCell::new(VecDeque::new()),
            has_unnotified_unread_outgoing_packets: Cell::new(false),
            unread_incoming_packets: RefCell::new(BinaryHeap::new()),
            sent_incoming_packets: RefCell::new(Vec::new()),
            outgoing_read_times: RefCell::new(Vec::new()),
            packet_statuses: RefCell::new(Vec::new()),
            timer: Cell::new(None),
            shutdown_requested: ShutdownRequested::new(),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub(crate) struct WanPacket {
    pub(crate) buffer: IpPacketBuffer,
    pub(crate) source: SocketAddr,
    pub(crate) dest: SocketAddr,
    pub(crate) sent_timestamp: u64,
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
        Some(self.cmp(other))
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub(crate) struct LocalPacket {
    pub(crate) buffer: IpPacketBuffer,
    pub(crate) timestamp: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct PacketStatus {
    pub(crate) direction: RelativeDirection,
    pub(crate) seqno: u64,
    pub(crate) tx_rx_epoch_times: Option<(u64, u64)>,
}

/// Hardware implementation for testing only.
#[derive(Debug)]
pub(crate) struct SimulatedHardware {
    peers: BTreeMap<SocketAddr, OneSideInfo>,
    /// All packets that have been sent from any of the sides are collected here in addition to the
    /// specific peers they were sent from/to.
    all_wan_packets: RefCell<Vec<WanPacket>>,
    packet_counter: Cell<u64>,
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
            all_wan_packets: RefCell::new(Vec::new()),
            packet_counter: Cell::new(0),
            packets_to_drop: HashSet::new(),
            packets_to_delay: HashMap::new(),
            default_delay,
            timestamp: 0,
        }
    }

    pub(crate) fn hardware(&self, addr: SocketAddr) -> OneSideHardware<'_> {
        OneSideHardware {
            simulated: self,
            our_addr: addr,
        }
    }

    /// as if the user pressed C-c
    pub(crate) fn request_shutdown(&self, addr: &SocketAddr) {
        self.peers
            .get(addr)
            .expect("non-existent `addr` to request_shutdown")
            .shutdown_requested
            .user_request_shutdown();
    }

    /// Un-request a shutdown. You should only call this when replacing a Core, else the Core might
    /// "remember" that shutdown was requested in the past and keep trying to shut down.
    pub(crate) fn clear_requested_shutdown(&mut self, addr: &SocketAddr) {
        self.peers
            .get_mut(addr)
            .expect("non-existent `addr` to clear_requested_shutdown")
            .shutdown_requested = ShutdownRequested::new();
    }

    pub(crate) fn shutdown_requested<'a>(&'a self, addr: &SocketAddr) -> &'a ShutdownRequested {
        &self
            .peers
            .get(addr)
            .expect("Non-existent `addr` to shutdown_requested")
            .shutdown_requested
    }

    // make an outgoing on the side with the given addr. Ie,
    pub(crate) fn make_outgoing_packet(&mut self, addr: &SocketAddr, packet: &[u8]) {
        let peer = self
            .peers
            .get(addr)
            .expect("non-existent `addr` to make_outgoing_packet");
        // SAFETY: Only holding borrow_mut in this scope where we have exclusive access to `self`,
        // so nobody else can possibly try and borrow it.
        let mut unread_outgoing = peer.unread_outgoing_packets.borrow_mut();
        unread_outgoing.push_back(IpPacketBuffer::new(packet));
        if unread_outgoing.len() == 1 {
            peer.has_unnotified_unread_outgoing_packets.set(true);
        }
    }

    // for the next few methods, since it's only for testing it's better to just clone rather than
    // to deal with returning a Ref
    pub(crate) fn sent_incoming_packets(&self, addr: &SocketAddr) -> Vec<LocalPacket> {
        self.peers[addr].sent_incoming_packets.borrow().clone()
    }

    pub(crate) fn sent_outgoing_packets(&self, addr: &SocketAddr) -> Vec<WanPacket> {
        self.peers[addr].sent_outgoing_packets.borrow().clone()
    }

    pub(crate) fn all_wan_packets(&self) -> Vec<WanPacket> {
        self.all_wan_packets.borrow().clone()
    }

    pub(crate) fn qdisc_settings(&self, addr: &SocketAddr) -> Option<QdiscSettings> {
        self.peers[addr].qdisc_settings.get()
    }

    pub(crate) fn packet_statuses(&self, addr: &SocketAddr) -> Vec<PacketStatus> {
        self.peers[addr].packet_statuses.borrow().clone()
    }

    pub(crate) fn drop_packet(&mut self, nth: u64) {
        let counter_to_drop = self.packet_counter.get() + nth;
        assert!(
            !self.packets_to_drop.contains(&counter_to_drop),
            "Already were gonna drop packet {} (nth: {})",
            counter_to_drop,
            nth
        );
        self.packets_to_drop.insert(counter_to_drop);
    }

    pub(crate) fn delay_packet(&mut self, nth: u64, duration: u64) {
        let counter_to_delay = self.packet_counter.get() + nth;
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
        // The strategy here is to (a) determine if anything has happened since the last
        while self.timestamp < stop_timestamp {
            let timestamp = self.timestamp;
            let mut next_event_timestamp = stop_timestamp;
            // track if ANY peer made progress at this timestamp, in which case we will need to
            // re-evaluate the next timestamp and perhaps call on_event again before advancing
            // timestamps.
            let mut has_event_at_present_timestamp_in_any_peer = false;

            // have to collect so we don't borrow self.peers
            for addr in self.peers.keys().cloned().collect::<Vec<SocketAddr>>() {
                let mut has_event_at_present_timestamp = false;
                let peer = self.peers.get(&addr).unwrap();
                let core = cores
                    .get_mut(&addr)
                    .expect("Missing addr from cores argument to run_until");

                // timer
                if let Some(timer) = peer.timer.get() {
                    assert!(
                        timer >= timestamp,
                        "We slept past a timer, or timer was set in the past, or Core didn't install a new timer after timer fired? Timer {timer} vs timestamp {timestamp}"
                    );
                    if timer == timestamp {
                        self.debug(format!("Timer triggered for {addr}"));
                        has_event_at_present_timestamp = true;
                    } else {
                        next_event_timestamp = min(next_event_timestamp, timer);
                    }
                }

                // read outgoing
                if peer.has_unnotified_unread_outgoing_packets.get() {
                    self.debug(format!("Unnotified unread outgoing packets for {addr}"));
                    peer.has_unnotified_unread_outgoing_packets.set(false);
                    has_event_at_present_timestamp = true;
                }

                // read incoming
                if let Some(incoming_packet) = peer.unread_incoming_packets.borrow().peek() {
                    if timestamp == incoming_packet.receipt_timestamp {
                        has_event_at_present_timestamp = true;
                    }
                    if timestamp < incoming_packet.receipt_timestamp {
                        next_event_timestamp =
                            min(next_event_timestamp, incoming_packet.receipt_timestamp);
                    }
                    // if the packet is in the past, then we have already notified the core via
                    // on_event since it was received (at the timestamp of the packet, either due to
                    // the packet itself or some other contemporaneous event), and do not need to
                    // notify again.
                }

                if has_event_at_present_timestamp {
                    has_event_at_present_timestamp_in_any_peer = true;
                    core.on_event(&self.hardware(addr));
                }
            }

            if !has_event_at_present_timestamp_in_any_peer {
                self.debug(format!(
                    "Done with present timestamp; advancing to {}ns",
                    next_event_timestamp
                ));
                self.timestamp = next_event_timestamp;
            }
        }
    }

    // idk if AsRef<str> is really the best signature here
    fn debug<S: AsRef<str>>(&self, msg: S) {
        log::debug!("{}ns: {}", self.timestamp, msg.as_ref());
    }
}

pub(crate) struct OneSideHardware<'a> {
    simulated: &'a SimulatedHardware,
    our_addr: SocketAddr,
}

impl OneSideHardware<'_> {
    fn our_side(&self) -> &OneSideInfo {
        self.simulated.peers.get(&self.our_addr).unwrap()
    }
}

impl Hardware for OneSideHardware<'_> {
    fn set_timer(&self, timestamp: u64) -> Option<u64> {
        let old_timestamp = self.our_side().timer.replace(Some(timestamp));
        self.simulated.debug(format!(
            "Setting timer for {} to {}ns (used to be {:?})",
            self.our_addr, timestamp, old_timestamp
        ));
        old_timestamp
    }

    fn get_timer(&self) -> Option<u64> {
        self.our_side().timer.get()
    }

    fn timestamp(&self) -> u64 {
        self.simulated.timestamp
    }

    fn epoch_timestamp(&self) -> u64 {
        // May want to change this
        self.timestamp()
    }

    // could one day be good to be able to simulate shutdowns separately in each direction?
    fn has_user_requested_shutdown(&self) -> bool {
        self.our_side()
            .shutdown_requested
            .has_user_requested_shutdown()
    }

    fn shutdown(&self) {
        self.our_side().shutdown_requested.core_request_shutdown();
    }

    fn read_outgoing_packet(&self) -> Option<ReadOutgoingPacket> {
        log::debug!("Read outgoing packet on {}", self.our_addr);
        self.our_side()
            .unread_outgoing_packets
            .borrow_mut()
            .pop_front()
            .map(|pkt| ReadOutgoingPacket {
                packet: pkt,
                recv_timestamp: self.timestamp(),
            })
    }

    fn read_incoming_packet(&self) -> Option<ReadIncomingPacket> {
        // I don't like holding Refmuts over relatively large portions of code like this, because
        // it's more likely you'll accidentally include some other call that also tries to access
        // the data in the RefCell. However, since this file is only for testing, I'm more ok with
        // it.
        let mut unread_incoming_packets = self.our_side().unread_incoming_packets.borrow_mut();
        if let Some(incoming_packet) = unread_incoming_packets.peek() {
            if self.timestamp() >= incoming_packet.receipt_timestamp {
                let incoming_packet = unread_incoming_packets.pop().unwrap();
                if let Some(connected_addr) = self.our_side().connected_addr.get() {
                    if connected_addr != incoming_packet.source {
                        self.simulated.debug(format!(
                            "Connected to {} but got packet from {} of size {}, on {}. Dropping.",
                            connected_addr,
                            incoming_packet.source,
                            incoming_packet.buffer.len(),
                            self.our_side().addr
                        ));
                    }
                }
                self.simulated.debug(format!(
                    "Reading incoming packet of size {} on {}, from {}",
                    incoming_packet.buffer.len(),
                    self.our_side().addr,
                    incoming_packet.source
                ));
                assert_eq!(incoming_packet.dest, self.our_side().addr);
                return Some(ReadIncomingPacket {
                    packet: incoming_packet.buffer,
                    peer: incoming_packet.source,
                });
            }
        }
        None
    }

    fn send_outgoing_packet(
        &self,
        packet: &[u8],
        destination: SocketAddr,
        timestamp: Option<u64>,
    ) -> Result<()> {
        let packet_counter = self.simulated.packet_counter.get();
        self.simulated.packet_counter.set(packet_counter + 1);

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

        let delay = self.simulated.default_delay
            + self
                .simulated
                .packets_to_delay
                .get(&packet_counter)
                .unwrap_or(&0);
        let receipt_timestamp = sent_timestamp + delay;
        self.simulated.debug(format!(
            "Sending packet from {} to {} of size {} (delay {}ns, to be received at {}ns)",
            self.our_addr,
            destination,
            packet.len(),
            delay,
            receipt_timestamp,
        ));
        let wan_packet = WanPacket {
            buffer: IpPacketBuffer::new(packet),
            sent_timestamp,
            receipt_timestamp,
            source: self.our_addr,
            dest: destination,
        };

        self.our_side()
            .sent_outgoing_packets
            .borrow_mut()
            .push(wan_packet.clone());
        self.simulated
            .all_wan_packets
            .borrow_mut()
            .push(wan_packet.clone());
        if let Some(destination_peer) = self.simulated.peers.get(&destination) {
            destination_peer
                .unread_incoming_packets
                .borrow_mut()
                .push(wan_packet);
        }

        Ok(())
    }

    fn send_incoming_packet(&self, packet: &[u8]) -> Result<()> {
        self.simulated.debug(format!(
            "Sending incoming packet on {} of size {}",
            self.our_addr,
            packet.len()
        ));
        let timestamp = self.timestamp();
        self.our_side()
            .sent_incoming_packets
            .borrow_mut()
            .push(LocalPacket {
                buffer: IpPacketBuffer::new(packet),
                timestamp,
            });
        Ok(())
    }

    fn socket_connect(&self, addr: &SocketAddr) -> Result<()> {
        self.our_side().connected_addr.set(Some(*addr));
        Ok(())
    }

    fn clear_event_listeners(&self) -> Result<()> {
        self.our_side().timer.set(None);
        self.our_side().connected_addr.set(None);
        Ok(())
    }

    fn mtu(&self, _peer: SocketAddr) -> Result<u16> {
        Ok(MAX_IP_PACKET_LENGTH.try_into().unwrap())
    }

    fn register_interval(&self, _duration: u64) {}

    fn register_packet_status(
        &self,
        direction: RelativeDirection,
        seqno: u64,
        tx_rx_epoch_times: Option<(u64, u64)>,
    ) {
        self.our_side()
            .packet_statuses
            .borrow_mut()
            .push(PacketStatus {
                direction,
                seqno,
                tx_rx_epoch_times,
            });
    }

    fn configure_qdisc(&self, settings: &QdiscSettings) -> Result<()> {
        self.our_side().qdisc_settings.replace(Some(*settings));
        Ok(())
    }
}
