use std::{
    net::SocketAddr,
    sync::mpsc,
    time::{Duration, Instant},
};

use crate::constants::{
    DTLS_MAX_HEADER_LENGTH, IPV4_HEADER_LENGTH, IPV6_HEADER_LENGTH, UDP_HEADER_LENGTH,
};

pub(crate) fn ns_to_str(ns: u64) -> String {
    humantime::format_duration(Duration::from_nanos(ns)).to_string()
}

pub(crate) fn ip_to_udp_length(ip_mtu: u16, peer: SocketAddr) -> u16 {
    match peer {
        SocketAddr::V4(_) => ip_mtu - IPV4_HEADER_LENGTH,
        SocketAddr::V6(_) => ip_mtu - IPV6_HEADER_LENGTH,
    }
}

pub(crate) fn ip_to_dtls_length(ip_mtu: u16, peer: SocketAddr) -> u16 {
    ip_to_udp_length(ip_mtu, peer) - UDP_HEADER_LENGTH
}

pub(crate) fn ip_to_i405_length(ip_mtu: u16, peer: SocketAddr) -> u16 {
    ip_to_dtls_length(ip_mtu, peer) - DTLS_MAX_HEADER_LENGTH
}

pub(crate) fn timestamp_to_instant(epoch: Instant, timestamp: u64) -> Instant {
    epoch + Duration::from_nanos(timestamp)
}

pub(crate) fn instant_to_timestamp(epoch: Instant, instant: Instant) -> u64 {
    instant
        .saturating_duration_since(epoch)
        .as_nanos()
        .try_into()
        .unwrap()
}

pub(crate) struct BasicStats {
    average: u64,
    variance: u64,
    p50: u64,
    p99: u64,
    p999: u64,
    max: u64,
}

impl BasicStats {
    // consume the vec just so that we can sort it internally
    pub(crate) fn from_vec(mut vec: Vec<u64>) -> BasicStats {
        vec.sort_unstable();
        let len = u64::try_from(vec.len()).unwrap();
        let average = vec.iter().sum::<u64>() / len;
        let variance = vec
            .iter()
            .map(|x| (std::cmp::max(*x, average) - std::cmp::min(*x, average)) ^ 2)
            .sum::<u64>()
            / len;
        BasicStats {
            average,
            variance,
            p50: vec[vec.len() / 2],
            p99: vec[vec.len() * 99 / 100],
            p999: vec[vec.len() * 999 / 1000],
            max: *vec.iter().max().unwrap(),
        }
    }
}

impl ToString for BasicStats {
    fn to_string(&self) -> String {
        format!(
            "Average : {}\nVariance: {}\nP50     : {}\nP99     : {}\nP99.9   : {}\nMax     : {}",
            ns_to_str(self.average),
            ns_to_str(self.variance),
            ns_to_str(self.p50),
            ns_to_str(self.p99),
            ns_to_str(self.p999),
            ns_to_str(self.max),
        )
    }
}

/// Automatically joins thread on drop.
struct JThread {
    join_handle: Option<std::thread::JoinHandle<()>>,
}

impl JThread {
    fn spawn<F: FnOnce() + Send + 'static>(f: F) -> Self {
        Self {
            join_handle: Some(std::thread::spawn(f)),
        }
    }
}

impl Drop for JThread {
    fn drop(&mut self) {
        if let Err(panic_payload) = std::mem::take(&mut self.join_handle).unwrap().join() {
            std::panic::resume_unwind(panic_payload);
        }
    }
}

// A channel that we can send stuff to. This is designed for threads that have internal logic which
// shuts down the thread once the channel closes; this way, as the ChannelThread is dropped, the
// channel will close, then we attempt to join the thread, and then the thread will cooperatively
// close, giving us a fully RAII-based cooperative thread closing mechanism.
pub(crate) struct ChannelThread<TX> {
    tx: mpsc::Sender<TX>,
    _jthread: JThread,
}

impl<TX> ChannelThread<TX> {
    pub(crate) fn spawn<F: FnOnce() + Send + 'static>(tx: mpsc::Sender<TX>, f: F) -> Self {
        Self {
            tx,
            _jthread: JThread::spawn(f),
        }
    }

    pub(crate) fn tx(&self) -> &mpsc::Sender<TX> {
        &self.tx
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn basic_ip_to_i405_length() {
        assert_eq!(
            ip_to_i405_length(1000 + 12 + 22 + 8 + 20, "127.0.0.1:1405".parse().unwrap()),
            1000
        );
        assert_eq!(
            ip_to_i405_length(1000 + 12 + 22 + 8 + 20, "[fe80::]:1405".parse().unwrap()),
            980
        );
    }
}
