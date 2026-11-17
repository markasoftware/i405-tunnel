use std::cell::RefCell;
use std::cmp::min;
use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet, VecDeque};
use std::net::SocketAddr;

use anyhow::Result;

use crate::array_array::IpPacketBuffer;
use crate::constants::MAX_IP_PACKET_LENGTH;
use crate::utils::RelativeDirection;
use crate::{core, hardware::Hardware};

use super::real_utils::QdiscSettings;
use super::{ReadIncomingPacket, ReadOutgoingPacket, ShutdownRequested};

#[derive(Debug, Clone)]
struct OneSideInfo {
    // if socket_connect has been called, then only accept incoming packets from this address
    connected_addr: Option<SocketAddr>,
    qdisc_settings: Option<QdiscSettings>,

    /// Packets already sent out by the side. A little bit cursed because it's in the order that
    /// send_outgoing_packet is called, rather than by send_timestamp, so it's possible for
    /// send_timestamps to not be in ascending order here.
    sent_outgoing_packets: Vec<WanPacket>,
    /// Packets to be read by this side, along with the time they'll become available (last part not
    /// impl'd yet).
    unread_outgoing_packets: VecDeque<IpPacketBuffer>,
    /// set to true whenever a packet is added to unread_outgoing_packets from empty, which will
    /// cause on_event to be called immediately on next run_until (at which point this will be reset
    /// to false).
    has_unnotified_unread_outgoing_packets: bool,

    /// second element of tuple is whether or not the core has been notified of this yet (ie, has it
    /// been woken up while this packet was in the heap)
    unread_incoming_packets: BinaryHeap<WanPacket>,
    sent_incoming_packets: Vec<LocalPacket>,
    // Need to set this true when either (a) a new incoming packet with timestamp == lowest
    // timestamp among all unread incoming packets is added or (b) the last unread incoming packet
    // <= timestamp is read.
    is_next_unread_incoming_packet_possibly_unnotified: bool,

    /// For each outgoing packet that's been read by the core, what timestamp was it read at?
    outgoing_read_times: Vec<u64>,

    /// Packet statuses registered by this peer
    packet_statuses: Vec<PacketStatus>,

    /// The next time we should wake up this thread.
    timer: Option<u64>,

    shutdown_requested: ShutdownRequested,
    has_unnotified_shutdown_requested: bool,
}

impl OneSideInfo {
    fn new() -> Self {
        Self {
            connected_addr: None,
            qdisc_settings: None,
            sent_outgoing_packets: Vec::new(),
            unread_outgoing_packets: VecDeque::new(),
            has_unnotified_unread_outgoing_packets: false,
            unread_incoming_packets: BinaryHeap::new(),
            sent_incoming_packets: Vec::new(),
            is_next_unread_incoming_packet_possibly_unnotified: true,
            outgoing_read_times: Vec::new(),
            packet_statuses: Vec::new(),
            timer: None,
            shutdown_requested: ShutdownRequested::new(),
            has_unnotified_shutdown_requested: false,
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
    inner: RefCell<SimulatedHardwareInner>,
}

#[derive(Debug)]
struct SimulatedHardwareInner {
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
        let inner = SimulatedHardwareInner {
            peers: BTreeMap::from_iter(
                peer_addrs
                    .into_iter()
                    .map(|addr| (addr, OneSideInfo::new())),
            ),
            all_wan_packets: Vec::new(),
            packet_counter: 0,
            packets_to_drop: HashSet::new(),
            packets_to_delay: HashMap::new(),
            default_delay,
            timestamp: 0,
        };
        Self {
            inner: RefCell::new(inner),
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
        let mut inner = self.inner.borrow_mut();
        let peer = inner
            .peers
            .get_mut(addr)
            .expect("non-existent `addr` to request_shutdown");
        peer.shutdown_requested.user_request_shutdown();
        peer.has_unnotified_shutdown_requested = true;
    }

    /// Reset all state related to a certain peer, including received packets etc. Call this if and
    /// only if you are changing out the Core associated with addr
    // TODO have the SimulatedHardware own the core, I think there's no reason not to now that we have on_event
    pub(crate) fn reset_peer_state(&self, addr: SocketAddr) {
        self.inner
            .borrow_mut()
            .peers
            .insert(addr, OneSideInfo::new())
            .expect("non-existent `addr` to reset_peer_state");
    }

    // make an outgoing on the side with the given addr. Ie,
    pub(crate) fn make_outgoing_packet(&self, addr: &SocketAddr, packet: &[u8]) {
        let mut inner = self.inner.borrow_mut();
        let peer = inner
            .peers
            .get_mut(addr)
            .expect("non-existent `addr` to make_outgoing_packet");
        peer.unread_outgoing_packets
            .push_back(IpPacketBuffer::new(packet));
        if peer.unread_outgoing_packets.len() == 1 {
            peer.has_unnotified_unread_outgoing_packets = true;
        }
    }

    fn peer(&self, addr: &SocketAddr) -> std::cell::Ref<'_, OneSideInfo> {
        std::cell::Ref::<'_, SimulatedHardwareInner>::map(self.inner.borrow(), |i| &i.peers[addr])
    }

    // for the next few methods, since it's only for testing it's better to just clone rather than
    // to deal with returning a Ref
    pub(crate) fn sent_incoming_packets(&self, addr: &SocketAddr) -> Vec<LocalPacket> {
        self.peer(addr).sent_incoming_packets.clone()
    }

    pub(crate) fn sent_outgoing_packets(&self, addr: &SocketAddr) -> Vec<WanPacket> {
        self.peer(addr).sent_outgoing_packets.clone()
    }

    pub(crate) fn all_wan_packets(&self) -> Vec<WanPacket> {
        self.inner.borrow().all_wan_packets.clone()
    }

    pub(crate) fn qdisc_settings(&self, addr: &SocketAddr) -> Option<QdiscSettings> {
        self.peer(addr).qdisc_settings
    }

    pub(crate) fn packet_statuses(&self, addr: &SocketAddr) -> Vec<PacketStatus> {
        self.peer(addr).packet_statuses.clone()
    }

    pub(crate) fn drop_packet(&self, nth: u64) {
        let mut inner = self.inner.borrow_mut();
        let counter_to_drop = inner.packet_counter + nth;
        assert!(
            !inner.packets_to_drop.contains(&counter_to_drop),
            "Already were gonna drop packet {} (nth: {})",
            counter_to_drop,
            nth
        );
        inner.packets_to_drop.insert(counter_to_drop);
    }

    pub(crate) fn delay_packet(&self, nth: u64, duration: u64) {
        let mut inner = self.inner.borrow_mut();
        let counter_to_delay = inner.packet_counter + nth;
        assert!(
            !inner.packets_to_delay.contains_key(&counter_to_delay),
            "Already were gonna delay packet {} (nth: {})",
            counter_to_delay,
            nth
        );
        assert!(
            !inner.packets_to_drop.contains(&counter_to_delay),
            "Can't delay packet we're gonna drop {} (nth: {})",
            counter_to_delay,
            nth
        );
        inner.packets_to_delay.insert(counter_to_delay, duration);
    }

    /// Read as "run until, but not including, stop_timestamp." Upon exit, the timestamp field will
    /// be equal to stop_timestamp, but no events at that timestamp will have been processed.
    pub(crate) fn run_until<'h>(
        &'h self,
        cores: &mut BTreeMap<SocketAddr, Box<dyn core::Core + 'h>>,
        stop_timestamp: u64,
    ) {
        let peer_addrs = self
            .inner
            .borrow()
            .peers
            .keys()
            .cloned()
            .collect::<Vec<SocketAddr>>();
        // The strategy here is to (a) determine if anything has happened since the last
        while self.inner.borrow().timestamp < stop_timestamp {
            let timestamp = self.inner.borrow().timestamp;
            let mut next_event_timestamp = stop_timestamp;
            // track if ANY peer made progress at this timestamp, in which case we will need to
            // re-evaluate the next timestamp and perhaps call on_event again before advancing
            // timestamps.
            let mut has_event_at_present_timestamp_in_any_peer = false;

            // have to collect so we don't borrow self.peers
            for addr in &peer_addrs {
                let mut has_event_at_present_timestamp = false;
                let core = cores
                    .get_mut(&addr)
                    .expect("Missing addr from cores argument to run_until");
                // ensure peer is dropped before we run on_event so the borrow is dropped
                {
                    let mut inner = self.inner.borrow_mut();
                    let peer = inner.peers.get_mut(&addr).unwrap();

                    // terminated
                    if peer.has_unnotified_shutdown_requested {
                        has_event_at_present_timestamp = true;
                    }
                    peer.has_unnotified_shutdown_requested = false;

                    // timer
                    if let Some(timer) = peer.timer {
                        assert!(
                            timer >= timestamp,
                            "We slept past a timer, or timer was set in the past, or Core didn't install a new timer after timer fired? Timer {timer} vs timestamp {timestamp}"
                        );
                        if timer == timestamp {
                            self.debug(format!("Timer triggered for {addr}"));
                            peer.timer = None;
                            has_event_at_present_timestamp = true;
                        } else {
                            next_event_timestamp = min(next_event_timestamp, timer);
                        }
                    }

                    // read outgoing
                    if std::mem::take(&mut peer.has_unnotified_unread_outgoing_packets) {
                        self.debug(format!("Unnotified unread outgoing packets for {addr}"));
                        has_event_at_present_timestamp = true;
                    }

                    // read incoming
                    if let Some(incoming_packet_receipt_timestamp) = peer
                        .unread_incoming_packets
                        .peek()
                        .map(|p| p.receipt_timestamp)
                    {
                        if timestamp == incoming_packet_receipt_timestamp
                            && std::mem::take(
                                &mut peer.is_next_unread_incoming_packet_possibly_unnotified,
                            )
                        {
                            has_event_at_present_timestamp = true;
                        }
                        if timestamp < incoming_packet_receipt_timestamp {
                            next_event_timestamp =
                                min(next_event_timestamp, incoming_packet_receipt_timestamp);
                        }
                        // if the packet is in the past, then we have already notified the core via
                        // on_event since it was received (at the timestamp of the packet, either due to
                        // the packet itself or some other contemporaneous event), and do not need to
                        // notify again.
                    }
                }

                if has_event_at_present_timestamp {
                    has_event_at_present_timestamp_in_any_peer = true;
                    core.on_event();
                }
            }

            if !has_event_at_present_timestamp_in_any_peer {
                self.debug(format!(
                    "Done with present timestamp; advancing to {}ns",
                    next_event_timestamp
                ));
                self.inner.borrow_mut().timestamp = next_event_timestamp;
            }
        }
    }

    // idk if AsRef<str> is really the best signature here
    fn debug<S: AsRef<str>>(&self, msg: S) {
        log::debug!("{}ns: {}", self.inner.borrow().timestamp, msg.as_ref());
    }
}

pub(crate) struct OneSideHardware<'a> {
    simulated: &'a SimulatedHardware,
    our_addr: SocketAddr,
}

impl OneSideHardware<'_> {
    fn our_side(&self) -> std::cell::RefMut<'_, OneSideInfo> {
        // I'd go a step further and borrow() on the OneSideInfo.inner, but then you need NestedRef crate :|
        std::cell::RefMut::<'_, SimulatedHardwareInner>::map(
            self.simulated.inner.borrow_mut(),
            |s| s.peers.get_mut(&self.our_addr).unwrap(),
        )
    }
}

impl Hardware for OneSideHardware<'_> {
    fn set_timer(&self, timestamp: u64) -> Option<u64> {
        let old_timestamp = std::mem::replace(&mut self.our_side().timer, Some(timestamp));
        self.simulated.debug(format!(
            "Setting timer for {} to {}ns (used to be {:?})",
            self.our_addr, timestamp, old_timestamp
        ));
        old_timestamp
    }

    fn timestamp(&self) -> u64 {
        self.simulated.inner.borrow().timestamp
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
        let timestamp = self.timestamp();
        self.our_side()
            .unread_outgoing_packets
            .pop_front()
            .map(|pkt| ReadOutgoingPacket {
                packet: pkt,
                recv_timestamp: timestamp,
            })
    }

    fn read_incoming_packet(&self) -> Option<ReadIncomingPacket> {
        // I don't like holding Refmuts over relatively large portions of code like this, because
        // it's more likely you'll accidentally include some other call that also tries to access
        // the data in the RefCell. However, since this file is only for testing, I'm more ok with
        // it.
        let timestamp = self.timestamp();
        let mut our_side = self.our_side();
        let connected_addr = our_side.connected_addr;
        let unread_incoming_packets = &mut our_side.unread_incoming_packets;
        if let Some(incoming_packet) = unread_incoming_packets.peek() {
            if timestamp >= incoming_packet.receipt_timestamp {
                let incoming_packet = unread_incoming_packets.pop().unwrap();
                if let Some(connected_addr) = connected_addr {
                    if connected_addr != incoming_packet.source {
                        self.simulated.debug(format!(
                            "Connected to {} but got packet from {} of size {}, on {}. Dropping.",
                            connected_addr,
                            incoming_packet.source,
                            incoming_packet.buffer.len(),
                            self.our_addr,
                        ));
                        // TODO we don't actually drop yet, it's annoying to do the logic right to
                        // loop through until a real packet. This is a BUG albeit a minor one since
                        // i don't think we use connect at all anywhere right now.
                    }
                }
                self.simulated.debug(format!(
                    "Reading incoming packet of size {} on {}, from {}",
                    incoming_packet.buffer.len(),
                    self.our_addr,
                    incoming_packet.source
                ));
                assert_eq!(incoming_packet.dest, self.our_addr);

                // if the /next/ packet is in the future, then we need to be notified of it! If the
                // next packet is at the same timestamp, or also less than the present timestamp,
                // then we've already been on_event'd while that packet is readable, and hence do
                // not need another on_event.
                if unread_incoming_packets
                    .peek()
                    .is_none_or(|p| timestamp < p.receipt_timestamp)
                {
                    our_side.is_next_unread_incoming_packet_possibly_unnotified = true;
                }

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
        let simulated_timestamp = self.timestamp();
        let mut simulated = self.simulated.inner.borrow_mut();
        let packet_counter = simulated.packet_counter;
        simulated.packet_counter += 1;

        let sent_timestamp = timestamp.unwrap_or(simulated_timestamp);

        if simulated.packets_to_drop.contains(&packet_counter) {
            self.simulated.debug(format!(
                "Dropping packet from {} to {} of size {} (sent at {}ns)",
                self.our_addr,
                destination,
                packet.len(),
                sent_timestamp
            ));
            return Ok(());
        }

        let delay = simulated.default_delay
            + simulated
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

        simulated
            .peers
            .get_mut(&self.our_addr)
            .unwrap()
            .sent_outgoing_packets
            .push(wan_packet.clone());
        simulated.all_wan_packets.push(wan_packet.clone());
        let timestamp = simulated.timestamp;
        if let Some(destination_peer) = simulated.peers.get_mut(&destination) {
            // this check could technically be tightened, to only if wan_packet.receipt_timestamp ==
            // (lowest receipt timestamp in unread_incoming_packets), but there's no need.
            if wan_packet.receipt_timestamp <= timestamp {
                destination_peer.is_next_unread_incoming_packet_possibly_unnotified = true;
            }
            destination_peer.unread_incoming_packets.push(wan_packet);
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
        self.our_side().sent_incoming_packets.push(LocalPacket {
            buffer: IpPacketBuffer::new(packet),
            timestamp,
        });
        Ok(())
    }

    fn socket_connect(&self, addr: &SocketAddr) -> Result<()> {
        self.our_side().connected_addr = Some(*addr);
        Ok(())
    }

    fn clear_event_listeners(&self) -> Result<()> {
        let mut our_side = self.our_side();
        our_side.timer = None;
        our_side.connected_addr = None;
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
        self.our_side().packet_statuses.push(PacketStatus {
            direction,
            seqno,
            tx_rx_epoch_times,
        });
    }

    fn configure_qdisc(&self, settings: &QdiscSettings) -> Result<()> {
        self.our_side().qdisc_settings = Some(*settings);
        Ok(())
    }
}
