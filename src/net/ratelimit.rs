// This file is part of Chhaya and is licensed under the GNU Affero General Public License v3.0 or later.
// See the LICENSE file in the project root for license details.

#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;
use std::net::IpAddr;

use libp2p_identity::PeerId;

/// Configuration for a token-bucket limiter measured in logical operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RateLimitParams {
    capacity: u32,
    replenish: u32,
    interval_secs: u64,
}

impl RateLimitParams {
    #[must_use]
    pub const fn new(capacity: u32, replenish: u32, interval_secs: u64) -> Self {
        Self {
            capacity,
            replenish,
            interval_secs,
        }
    }

    #[must_use]
    pub const fn unbounded() -> Self {
        Self::new(u32::MAX, u32::MAX, 0)
    }

    const fn is_unbounded(&self) -> bool {
        self.interval_secs == 0
    }
}

#[derive(Clone, Debug)]
struct TokenBucket {
    capacity: u32,
    tokens: u32,
    replenish: u32,
    interval_secs: u64,
    last_refill: Option<u64>,
}

impl TokenBucket {
    fn new(params: RateLimitParams) -> Self {
        Self {
            capacity: params.capacity,
            tokens: params.capacity,
            replenish: params.replenish,
            interval_secs: params.interval_secs,
            last_refill: None,
        }
    }

    fn refill(&mut self, now: u64) {
        if self.interval_secs == 0 {
            self.tokens = self.capacity;
            self.last_refill = Some(now);
            return;
        }
        match self.last_refill {
            Some(last) => {
                if now <= last {
                    return;
                }
                let elapsed = now.saturating_sub(last);
                let intervals = elapsed / self.interval_secs;
                if intervals == 0 {
                    return;
                }
                let additional = intervals.saturating_mul(self.replenish as u64);
                let new_tokens = (self.tokens as u64).saturating_add(additional);
                self.tokens = new_tokens.min(self.capacity as u64) as u32;
                let advanced = intervals.saturating_mul(self.interval_secs);
                self.last_refill = Some(last.saturating_add(advanced));
            }
            None => {
                self.tokens = self.capacity;
                self.last_refill = Some(now);
            }
        }
    }

    fn try_consume(&mut self, now: u64, tokens: u32) -> bool {
        if self.interval_secs == 0 {
            return true;
        }
        self.refill(now);
        if self.tokens >= tokens {
            self.tokens -= tokens;
            true
        } else {
            false
        }
    }
}

/// Combined IP and peer identity token-bucket rate limiter.
#[derive(Debug)]
pub struct RateLimiter {
    ip_params: RateLimitParams,
    peer_params: RateLimitParams,
    per_ip: HashMap<IpAddr, TokenBucket>,
    per_peer: HashMap<PeerId, TokenBucket>,
    cost: u32,
}

impl RateLimiter {
    #[must_use]
    pub fn new(ip_params: RateLimitParams, peer_params: RateLimitParams) -> Self {
        Self {
            ip_params,
            peer_params,
            per_ip: HashMap::new(),
            per_peer: HashMap::new(),
            cost: 1,
        }
    }

    #[must_use]
    pub fn unlimited() -> Self {
        Self::new(RateLimitParams::unbounded(), RateLimitParams::unbounded())
    }

    pub fn try_acquire(&mut self, now: u64, ip: Option<IpAddr>, peer: Option<&PeerId>) -> bool {
        if let Some(addr) = ip {
            if !self.consume_ip(now, addr) {
                return false;
            }
        }
        if let Some(peer_id) = peer {
            if !self.consume_peer(now, peer_id) {
                return false;
            }
        }
        true
    }

    fn consume_ip(&mut self, now: u64, ip: IpAddr) -> bool {
        if self.ip_params.is_unbounded() {
            return true;
        }
        let bucket = self
            .per_ip
            .entry(ip)
            .or_insert_with(|| TokenBucket::new(self.ip_params));
        bucket.try_consume(now, self.cost)
    }

    fn consume_peer(&mut self, now: u64, peer: &PeerId) -> bool {
        if self.peer_params.is_unbounded() {
            return true;
        }
        let bucket = self
            .per_peer
            .entry(*peer)
            .or_insert_with(|| TokenBucket::new(self.peer_params));
        bucket.try_consume(now, self.cost)
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::unlimited()
    }
}

#[cfg(test)]
mod tests {
    use super::{RateLimitParams, RateLimiter};
    use libp2p_identity::{Keypair, PeerId};
    use std::net::{IpAddr, Ipv4Addr};

    fn random_peer_id() -> PeerId {
        let kp = Keypair::generate_ed25519();
        PeerId::from_public_key(&kp.public())
    }

    #[test]
    fn throttle_and_refill() {
        let mut limiter = RateLimiter::new(
            RateLimitParams::new(1, 1, 10),
            RateLimitParams::new(1, 1, 10),
        );
        let ip = IpAddr::from(Ipv4Addr::new(10, 0, 0, 1));
        let peer = random_peer_id();
        assert!(limiter.try_acquire(100, Some(ip), Some(&peer)));
        assert!(!limiter.try_acquire(101, Some(ip), Some(&peer)));
        assert!(limiter.try_acquire(120, Some(ip), Some(&peer)));
    }

    #[test]
    fn unlimited_always_allows() {
        let mut limiter = RateLimiter::unlimited();
        let ip = IpAddr::from(Ipv4Addr::new(203, 0, 113, 5));
        let peer = random_peer_id();
        for ts in [0, 1, 10, 10_000] {
            assert!(limiter.try_acquire(ts, Some(ip), Some(&peer)));
        }
    }
}
