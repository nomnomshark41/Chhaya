#![forbid(unsafe_code)]

use libipld::cid::Cid;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::fs;
use std::io;
use std::io::ErrorKind;
use std::path::Path;

const DEFAULT_CHECKPOINT_KEEP: usize = 8;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct PinTarget {
    cid: Cid,
    tree_size: u64,
}

/// Tracks which directory artifacts should remain pinned on the local node.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PinPolicy {
    keep_checkpoints: usize,
    current_sth: Option<PinTarget>,
    checkpoints: VecDeque<PinTarget>,
    active_bundles: BTreeMap<String, Cid>,
}

/// Single CID pin entry along with the reasons it must be retained.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PinRecord {
    pub cid: Cid,
    pub reasons: BTreeSet<PinReason>,
}

impl PinRecord {
    fn new(cid: Cid) -> Self {
        Self {
            cid,
            reasons: BTreeSet::new(),
        }
    }
}

/// Reasons why a CID should remain pinned to satisfy audit requirements.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum PinReason {
    CurrentSth { tree_size: u64 },
    Consistency { tree_size: u64 },
    Bundle,
}

impl fmt::Display for PinReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CurrentSth { tree_size } => {
                write!(f, "current STH (tree size {tree_size})")
            }
            Self::Consistency { tree_size } => {
                write!(f, "consistency checkpoint (tree size {tree_size})")
            }
            Self::Bundle => f.write_str("active bundle"),
        }
    }
}

impl Ord for PinReason {
    fn cmp(&self, other: &Self) -> Ordering {
        use PinReason::{Bundle, Consistency, CurrentSth};
        match (self, other) {
            (CurrentSth { tree_size: a }, CurrentSth { tree_size: b }) => a.cmp(b),
            (CurrentSth { .. }, _) => Ordering::Less,
            (_, CurrentSth { .. }) => Ordering::Greater,
            (Bundle, Bundle) => Ordering::Equal,
            (Bundle, Consistency { .. }) => Ordering::Less,
            (Consistency { .. }, Bundle) => Ordering::Greater,
            (Consistency { tree_size: a }, Consistency { tree_size: b }) => a.cmp(b),
        }
    }
}

impl PartialOrd for PinReason {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Default for PinPolicy {
    fn default() -> Self {
        Self::new(DEFAULT_CHECKPOINT_KEEP)
    }
}

impl PinPolicy {
    pub fn new(keep_checkpoints: usize) -> Self {
        Self {
            keep_checkpoints,
            current_sth: None,
            checkpoints: VecDeque::new(),
            active_bundles: BTreeMap::new(),
        }
    }

    pub fn keep_checkpoints(&self) -> usize {
        self.keep_checkpoints
    }

    pub fn checkpoint_count(&self) -> usize {
        self.checkpoints.len()
    }

    pub fn current_sth(&self) -> Option<(&Cid, u64)> {
        self.current_sth
            .as_ref()
            .map(|target| (&target.cid, target.tree_size))
    }

    pub fn checkpoints(&self) -> impl Iterator<Item = (&Cid, u64)> {
        self.checkpoints
            .iter()
            .map(|target| (&target.cid, target.tree_size))
    }

    pub fn active_bundle_cids(&self) -> impl Iterator<Item = &Cid> {
        self.active_bundles.values()
    }

    pub fn update_current_sth(&mut self, root_cid: Cid, tree_size: u64) {
        if self
            .current_sth
            .as_ref()
            .is_some_and(|current| current.cid == root_cid && current.tree_size == tree_size)
        {
            return;
        }
        if let Some(previous) = self.current_sth.take() {
            self.push_checkpoint(previous);
        }
        self.current_sth = Some(PinTarget {
            cid: root_cid,
            tree_size,
        });
    }

    pub fn add_consistency_checkpoint(&mut self, root_cid: Cid, tree_size: u64) {
        let checkpoint = PinTarget {
            cid: root_cid,
            tree_size,
        };
        self.push_checkpoint(checkpoint);
    }

    pub fn add_active_bundle(&mut self, cid: Cid) {
        let key = cid.to_string();
        self.active_bundles.insert(key, cid);
    }

    pub fn remove_active_bundle(&mut self, cid: &Cid) -> bool {
        self.active_bundles.remove(&cid.to_string()).is_some()
    }

    pub fn clear_active_bundles(&mut self) {
        self.active_bundles.clear();
    }

    pub fn prune_checkpoints_to(&mut self, keep: usize) -> usize {
        self.keep_checkpoints = keep;
        self.prune_checkpoints_internal()
    }

    pub fn pins(&self) -> Vec<PinRecord> {
        let mut records: BTreeMap<String, PinRecord> = BTreeMap::new();

        if let Some(current) = &self.current_sth {
            let key = current.cid.to_string();
            let entry = records
                .entry(key)
                .or_insert_with(|| PinRecord::new(current.cid));
            entry.reasons.insert(PinReason::CurrentSth {
                tree_size: current.tree_size,
            });
        }

        for checkpoint in &self.checkpoints {
            let key = checkpoint.cid.to_string();
            let entry = records
                .entry(key)
                .or_insert_with(|| PinRecord::new(checkpoint.cid));
            entry.reasons.insert(PinReason::Consistency {
                tree_size: checkpoint.tree_size,
            });
        }

        for (key, cid) in &self.active_bundles {
            let entry = records
                .entry(key.clone())
                .or_insert_with(|| PinRecord::new(*cid));
            entry.reasons.insert(PinReason::Bundle);
        }

        records.into_values().collect()
    }

    pub fn load_from_path<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let path = path.as_ref();
        match fs::read(path) {
            Ok(bytes) => {
                let policy: PinPolicy = serde_json::from_slice(&bytes)
                    .map_err(|error| io::Error::new(ErrorKind::InvalidData, error))?;
                Ok(policy)
            }
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(error),
        }
    }

    pub fn save_to_path<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let mut copy = self.clone();
        copy.prune_checkpoints_internal();
        let data = serde_json::to_vec_pretty(&copy).map_err(io::Error::other)?;
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, &data)?;
        fs::rename(&tmp, path)?;
        Ok(())
    }

    fn push_checkpoint(&mut self, checkpoint: PinTarget) {
        self.checkpoints.retain(|existing| {
            existing.cid != checkpoint.cid || existing.tree_size != checkpoint.tree_size
        });
        if self.keep_checkpoints == 0 {
            return;
        }
        self.checkpoints.push_back(checkpoint);
        self.prune_checkpoints_internal();
    }

    fn prune_checkpoints_internal(&mut self) -> usize {
        let mut removed = 0usize;
        while self.checkpoints.len() > self.keep_checkpoints {
            self.checkpoints.pop_front();
            removed += 1;
        }
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use multihash::{Code, MultihashDigest};

    fn cid_from_bytes(bytes: &[u8]) -> Cid {
        let hash = Code::Sha2_256.digest(bytes);
        Cid::new_v1(u64::from(libipld::cbor::DagCborCodec), hash)
    }

    #[test]
    fn current_sth_replaced_and_checkpointed() {
        let cid_a = cid_from_bytes(b"a");
        let cid_b = cid_from_bytes(b"b");
        let mut policy = PinPolicy::new(2);

        policy.update_current_sth(cid_a, 10);
        assert_eq!(policy.current_sth(), Some((&cid_a, 10)));
        assert_eq!(policy.checkpoint_count(), 0);

        policy.update_current_sth(cid_b, 20);
        assert_eq!(policy.current_sth(), Some((&cid_b, 20)));
        let checkpoints: Vec<_> = policy.checkpoints().collect();
        assert_eq!(checkpoints.len(), 1);
        assert_eq!(checkpoints[0], (&cid_a, 10));

        let pins = policy.pins();
        assert_eq!(pins.len(), 2);
    }

    #[test]
    fn prune_checkpoints_respects_limit() {
        let cid_a = cid_from_bytes(b"a");
        let cid_b = cid_from_bytes(b"b");
        let cid_c = cid_from_bytes(b"c");
        let mut policy = PinPolicy::new(1);

        policy.add_consistency_checkpoint(cid_a, 10);
        policy.add_consistency_checkpoint(cid_b, 20);
        assert_eq!(policy.checkpoint_count(), 1);
        assert_eq!(policy.checkpoints().next(), Some((&cid_b, 20)));

        let removed = policy.prune_checkpoints_to(0);
        assert_eq!(removed, 1);
        assert_eq!(policy.checkpoint_count(), 0);

        policy.prune_checkpoints_to(1);
        policy.update_current_sth(cid_c, 30);
        policy.update_current_sth(cid_a, 40);
        let pins = policy.pins();
        assert!(pins.iter().any(|record| record.cid == cid_a));
        assert!(pins.iter().any(|record| record.cid == cid_c));
    }

    #[test]
    fn bundle_tracking_adds_pin_reason() {
        let cid_a = cid_from_bytes(b"bundle");
        let mut policy = PinPolicy::default();
        policy.add_active_bundle(cid_a);
        let pins = policy.pins();
        assert_eq!(pins.len(), 1);
        let record = &pins[0];
        assert_eq!(record.cid, cid_a);
        assert!(record.reasons.contains(&PinReason::Bundle));
    }
}
