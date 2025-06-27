use std::collections::VecDeque;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::utils::{BasicStats, ChannelThread};

const MAX_NUM_INTERVALS: usize = 16;
const MAX_NUM_RECENT_PACKETS: usize = 16;

pub(crate) struct DeviationStats {
    intervals: Vec<Interval>,
    recent_packets: VecDeque<Packet>,
    // once an interval is completed, the deviation goes here:
    deviations: Vec<i64>,
}

struct Interval {
    left_id: u64,
    right_id: u64,
    expected_duration: u64,
    // filled in after we actually receive the LHS
    left_timestamp: Option<u64>,
    right_timestamp: Option<u64>,
}

struct Packet {
    id: u64,
    timestamp: u64,
}

/// Return a deviation if this packet completed an interval, else None. Caller is responsible
/// from ensuring interval is removed if Some(..) is returned.
fn try_complete_interval(packet: &Packet, interval: &mut Interval) -> Option<i64> {
    if packet.id == interval.left_id {
        assert!(interval.left_timestamp.is_none());
        interval.left_timestamp = Some(packet.timestamp);
    }
    if packet.id == interval.right_id {
        assert!(interval.right_timestamp.is_none());
        interval.right_timestamp = Some(packet.timestamp);
    }
    if let (Some(left_timestamp), Some(right_timestamp)) =
        (interval.left_timestamp, interval.right_timestamp)
    {
        // this interval is done, add its deviation to the list but nothing more
        let deviation = i64::try_from(right_timestamp).unwrap()
            - i64::try_from(left_timestamp).unwrap()
            - i64::try_from(interval.expected_duration).unwrap();
        Some(deviation)
    } else {
        None
    }
}

impl DeviationStats {
    pub(crate) fn new() -> DeviationStats {
        DeviationStats {
            intervals: Vec::new(),
            recent_packets: VecDeque::new(),
            deviations: Vec::new(),
        }
    }

    pub(crate) fn register_interval(
        &mut self,
        left_id: u64,
        right_id: u64,
        expected_duration: u64,
    ) {
        let mut new_interval = Interval {
            left_id,
            right_id,
            expected_duration,
            left_timestamp: None,
            right_timestamp: None,
        };
        for packet in &self.recent_packets {
            if let Some(deviation) = try_complete_interval(packet, &mut new_interval) {
                self.deviations.push(deviation);
                return;
            }
        }

        if self.intervals.len() >= MAX_NUM_INTERVALS {
            log::warn!(
                "Dropping an interval from interval length statistics because we were keeping track of too many"
            );
            self.intervals[0] = new_interval;
        } else {
            self.intervals.push(new_interval);
        }
    }

    pub(crate) fn register_packet(&mut self, id: u64, timestamp: u64) {
        if self.recent_packets.len() == MAX_NUM_RECENT_PACKETS {
            self.recent_packets.pop_front();
        }
        let packet = Packet { id, timestamp };
        let intervals = std::mem::take(&mut self.intervals);
        for mut interval in intervals {
            if let Some(deviation) = try_complete_interval(&packet, &mut interval) {
                self.deviations.push(deviation);
            } else {
                // if not complete, keep the interval around
                self.intervals.push(interval);
            }
        }
        self.recent_packets.push_back(packet);
    }

    /// Get all the deviations since the last time this fn was called.
    pub(crate) fn pop_deviations(&mut self) -> Vec<i64> {
        std::mem::take(&mut self.deviations)
    }

    pub(crate) fn pop_deviations_to_human_readable_stats(&mut self) -> String {
        let deviations = self.pop_deviations();
        if deviations.is_empty() {
            return "No deviations measured".to_string();
        }

        let deviations: Vec<u64> = deviations
            .iter()
            .map(|x| x.abs().try_into().unwrap())
            .collect();
        "Outgoing send timestamp deviations:\n".to_string()
            + &BasicStats::from_vec(deviations).to_string()
    }
}

pub(crate) struct DeviationStatsThread {
    channel_thread: ChannelThread<IntervalStatsCommand>,
}

enum IntervalStatsCommand {
    RegisterInterval {
        left_id: u64,
        right_id: u64,
        expected_duration: u64,
    },
    RegisterPacket {
        id: u64,
        timestamp: u64,
    },
}

impl DeviationStatsThread {
    pub(crate) fn spawn(report_interval: Duration) -> DeviationStatsThread {
        let (tx, rx) = mpsc::channel();
        let thread_fn = move || {
            let mut interval_stats = DeviationStats::new();
            let mut last_summary_time = Instant::now();
            while let Ok(command) = rx.recv() {
                match command {
                    IntervalStatsCommand::RegisterInterval {
                        left_id,
                        right_id,
                        expected_duration,
                    } => {
                        interval_stats.register_interval(left_id, right_id, expected_duration);
                    }
                    IntervalStatsCommand::RegisterPacket { id, timestamp } => {
                        interval_stats.register_packet(id, timestamp);
                    }
                }
                if Instant::now().saturating_duration_since(last_summary_time) > report_interval {
                    println!(
                        "{}",
                        interval_stats.pop_deviations_to_human_readable_stats()
                    );
                    last_summary_time = Instant::now();
                }
            }
        };
        DeviationStatsThread {
            channel_thread: ChannelThread::spawn(tx, thread_fn),
        }
    }

    pub(crate) fn register_interval(&self, left_id: u64, right_id: u64, expected_duration: u64) {
        self.channel_thread
            .tx()
            .send(IntervalStatsCommand::RegisterInterval {
                left_id,
                right_id,
                expected_duration,
            })
            .unwrap();
    }

    pub(crate) fn register_packet(&self, id: u64, timestamp: u64) {
        self.channel_thread
            .tx()
            .send(IntervalStatsCommand::RegisterPacket { id, timestamp })
            .unwrap();
    }
}

// these tests are written by AI (and found a bug nevertheless!)
#[cfg(test)]
mod test {
    use super::{DeviationStats, MAX_NUM_INTERVALS, MAX_NUM_RECENT_PACKETS};

    #[test]
    fn packets_then_intervals() {
        let mut stats = DeviationStats::new();
        stats.register_packet(1, 100);
        stats.register_packet(2, 210);
        stats.register_packet(3, 300);

        stats.register_interval(1, 2, 100); // expected 100, actual 110, deviation 10
        stats.register_interval(2, 3, 100); // expected 100, actual 90, deviation -10

        let mut deviations = stats.pop_deviations();
        deviations.sort_unstable();
        assert_eq!(deviations, vec![-10, 10]);
    }

    #[test]
    fn intervals_then_packets() {
        let mut stats = DeviationStats::new();

        stats.register_interval(1, 2, 100); // expected 100, actual 110, deviation 10
        stats.register_interval(2, 3, 100); // expected 100, actual 90, deviation -10

        stats.register_packet(1, 100);
        stats.register_packet(2, 210);
        stats.register_packet(3, 300);

        let mut deviations = stats.pop_deviations();
        deviations.sort_unstable();
        assert_eq!(deviations, vec![-10, 10]);
    }

    #[test]
    fn too_many_intervals() {
        let mut stats = DeviationStats::new();

        // Register MAX_NUM_INTERVALS intervals that will never be completed
        for i in 0..u64::try_from(MAX_NUM_INTERVALS).unwrap() {
            stats.register_interval(1000 + i, 2000 + i, 100);
        }

        // This one should push out the first one (id 1000 -> 2000)
        stats.register_interval(1, 2, 100);

        // Complete the one we just added
        stats.register_packet(1, 100);
        stats.register_packet(2, 210); // deviation 10

        // Try to complete the one that should have been pushed out
        stats.register_packet(1000, 100000);
        stats.register_packet(2000, 200000);

        let deviations = stats.pop_deviations();
        assert_eq!(deviations, vec![10]);
    }

    #[test]
    fn too_many_packets() {
        let mut stats = DeviationStats::new();

        for i in 0..u64::try_from(MAX_NUM_RECENT_PACKETS).unwrap() {
            stats.register_packet(i, i * 100);
        }

        // This one should push out packet 0
        let last_packet_id = u64::try_from(MAX_NUM_RECENT_PACKETS).unwrap();
        stats.register_packet(last_packet_id, last_packet_id * 100);

        // This interval uses packet 0, which should be gone
        stats.register_interval(0, 1, 100);

        // This interval uses recent packets
        stats.register_interval(last_packet_id - 1, last_packet_id, 100); // expected 100, actual 100, deviation 0

        let deviations = stats.pop_deviations();
        assert_eq!(deviations, vec![0]);
    }

    #[test]
    fn pop_deviations_clears_list() {
        let mut stats = DeviationStats::new();
        stats.register_packet(1, 100);
        stats.register_packet(2, 210);
        stats.register_interval(1, 2, 100); // deviation 10

        assert_eq!(stats.pop_deviations(), vec![10]);
        assert!(stats.pop_deviations().is_empty());
    }
}
