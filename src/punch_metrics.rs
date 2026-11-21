use hbb_common::{rendezvous_proto::P2pFeedback, try_into_v4};
use std::{
    net::SocketAddr,
    sync::atomic::{AtomicU64, Ordering::Relaxed},
};

#[derive(Default)]
pub(crate) struct Metrics {
    enabled: bool,
    observer_v4: AtomicU64,
    observer_v6: AtomicU64,
    observer_rejected: AtomicU64,
    observer_replied: AtomicU64,
    observer_send_failed: AtomicU64,
    outcomes: [AtomicU64; 4],
    duration_ms: AtomicU64,
    local_candidates: AtomicU64,
    peer_candidates: AtomicU64,
    probes: AtomicU64,
    observer_counts: [AtomicU64; 9],
}

impl Metrics {
    pub(crate) fn new(enabled: bool) -> Self {
        Self { enabled, ..Self::default() }
    }

    pub(crate) fn enabled(&self) -> bool {
        self.enabled
    }

    pub(crate) fn observer(&self, source: SocketAddr, valid: bool) {
        if !self.enabled {
            return;
        }
        if try_into_v4(source).is_ipv4() {
            self.observer_v4.fetch_add(1, Relaxed);
        } else {
            self.observer_v6.fetch_add(1, Relaxed);
        }
        if !valid {
            self.observer_rejected.fetch_add(1, Relaxed);
        }
    }

    pub(crate) fn observer_reply(&self, sent: bool) {
        if self.enabled {
            let count = if sent { &self.observer_replied } else { &self.observer_send_failed };
            count.fetch_add(1, Relaxed);
        }
    }

    pub(crate) fn report(&self, report: P2pFeedback) {
        if !self.enabled || report.revision != 1 || report.phase != 1
            || report.elapsed_ms > 90_000 || report.local_candidates > 500
            || report.peer_candidates > 500 || report.probes_written > 10_000
            || (!report.observer_counts.is_empty() && report.observer_counts.len() != self.observer_counts.len())
            || report.observer_counts.iter().any(|count| *count > 2048)
        {
            return;
        }
        let Some(outcome) = report.outcome.checked_sub(1)
            .and_then(|index| self.outcomes.get(index as usize))
        else {
            return;
        };
        outcome.fetch_add(1, Relaxed);
        self.duration_ms.fetch_add(u64::from(report.elapsed_ms), Relaxed);
        self.local_candidates.fetch_add(u64::from(report.local_candidates), Relaxed);
        self.peer_candidates.fetch_add(u64::from(report.peer_candidates), Relaxed);
        self.probes.fetch_add(u64::from(report.probes_written), Relaxed);
        for (total, count) in self.observer_counts.iter().zip(report.observer_counts) {
            total.fetch_add(u64::from(count), Relaxed);
        }
    }

    pub(crate) fn snapshot(&self) -> String {
        if !self.enabled {
            return "P2P feedback disabled\n".into();
        }
        format!(
            "observer_ipv4={} observer_ipv6={} observer_rejected={} observer_replied={} observer_send_failed={} full_ready={} full_empty={} full_failed={} full_tcp53_blocked={} elapsed_ms={} local_candidates={} peer_candidates={} probes={}\nseed [native_ipv4,nat64,bind_failed,sent,send_failed,timeout,invalid_reply,mapping_rejected,verified]={:?}\n",
            self.observer_v4.load(Relaxed),
            self.observer_v6.load(Relaxed),
            self.observer_rejected.load(Relaxed),
            self.observer_replied.load(Relaxed),
            self.observer_send_failed.load(Relaxed),
            self.outcomes[0].load(Relaxed),
            self.outcomes[1].load(Relaxed),
            self.outcomes[2].load(Relaxed),
            self.outcomes[3].load(Relaxed),
            self.duration_ms.load(Relaxed),
            self.local_candidates.load(Relaxed),
            self.peer_candidates.load(Relaxed),
            self.probes.load(Relaxed),
            self.observer_counts.each_ref().map(|count| count.load(Relaxed)),
        )
    }
}
