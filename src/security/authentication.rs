use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthChallenge {
    pub nonce: String,
    pub issued_unix_seconds: u64,
    pub expires_after_seconds: u64,
}

impl AuthChallenge {
    pub fn new(expires_after_seconds: u64) -> Self {
        let unique_material = format!("{}:{}", Uuid::new_v4(), now_unix_seconds());
        Self {
            nonce: crate::security::fingerprint::sha256_fingerprint(unique_material.as_bytes()),
            issued_unix_seconds: now_unix_seconds(),
            expires_after_seconds,
        }
    }

    pub fn is_expired_at(&self, now_unix_seconds: u64) -> bool {
        now_unix_seconds
            > self
                .issued_unix_seconds
                .saturating_add(self.expires_after_seconds)
    }
}

/// In-memory replay protection for a single device session.  A challenge is
/// accepted once, only within its lifetime, and the map is bounded.
#[derive(Debug)]
pub struct ReplayGuard {
    seen: HashMap<String, u64>,
    max_entries: usize,
    clock_skew_seconds: u64,
}

impl ReplayGuard {
    pub fn new(max_entries: usize, clock_skew_seconds: u64) -> Self {
        Self {
            seen: HashMap::new(),
            max_entries: max_entries.max(1),
            clock_skew_seconds,
        }
    }

    pub fn accept(&mut self, challenge: &AuthChallenge, now_unix_seconds: u64) -> bool {
        self.purge(now_unix_seconds);
        if challenge.issued_unix_seconds > now_unix_seconds.saturating_add(self.clock_skew_seconds)
            || challenge.is_expired_at(now_unix_seconds)
            || self.seen.contains_key(&challenge.nonce)
        {
            return false;
        }

        if self.seen.len() >= self.max_entries {
            if let Some(oldest) = self
                .seen
                .iter()
                .min_by_key(|(_, issued)| **issued)
                .map(|(nonce, _)| nonce.clone())
            {
                self.seen.remove(&oldest);
            }
        }
        self.seen
            .insert(challenge.nonce.clone(), challenge.issued_unix_seconds);
        true
    }

    fn purge(&mut self, now_unix_seconds: u64) {
        self.seen.retain(|_, issued| {
            now_unix_seconds.saturating_sub(*issued) <= self.clock_skew_seconds
        });
    }
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}
