use hex::encode as hex_encode;
use std::collections::{BTreeMap, HashSet};
use std::error::Error as StdError;
use std::fmt;

/// Signed tree head and witnesses fetched from a VKD log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SthBundle {
    pub log_id: Vec<u8>,
    pub root_hash: [u8; 32],
    pub tree_size: u64,
    pub sth_time: u64,
    pub log_signature: Vec<u8>,
    pub witness_signatures: Vec<Vec<u8>>,
}

/// Policy describing how many logs must agree before trusting an STH cluster.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct MultiLogPolicy {
    pub witness_threshold: usize,
    pub min_logs: usize,
    pub agreement_ratio: f64,
}

impl MultiLogPolicy {
    pub fn required_agreement(&self, total_logs: usize) -> usize {
        if total_logs == 0 {
            return 0;
        }
        let ratio_target = self.agreement_ratio.clamp(0.0, 1.0);
        let ratio_count = (ratio_target * total_logs as f64).ceil() as usize;
        ratio_count.max(self.min_logs)
    }
}

/// Result of merging consistent STH bundles across logs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Concordance {
    pub root_hash: [u8; 32],
    pub tree_size: u64,
    pub logs: Vec<Vec<u8>>,
}

/// Failures that prevent forming a concordant view of VKD logs.
#[derive(Debug, PartialEq)]
pub enum ConcordanceError {
    EmptyInput,
    DuplicateLogId(Vec<u8>),
    InsufficientWitnesses {
        log_id: Vec<u8>,
        found: usize,
        required: usize,
    },
    InsufficientLogs {
        required: usize,
        found: usize,
    },
    InvalidAgreementRatio(f64),
    NoAgreement {
        required: usize,
        best: usize,
    },
}

impl fmt::Display for ConcordanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInput => write!(f, "no STH bundles provided"),
            Self::DuplicateLogId(log_id) => {
                write!(f, "duplicate log identifier: {}", hex_encode(log_id))
            }
            Self::InsufficientWitnesses {
                log_id,
                found,
                required,
            } => {
                write!(
                    f,
                    "log {} only had {found} unique witnesses (requires {required})",
                    hex_encode(log_id)
                )
            }
            Self::InsufficientLogs { required, found } => {
                write!(f, "need at least {required} logs, only received {found}")
            }
            Self::InvalidAgreementRatio(ratio) => {
                write!(f, "invalid agreement ratio: {ratio}")
            }
            Self::NoAgreement { required, best } => {
                write!(
                    f,
                    "no concordant cluster reached {required} logs (best observed {best})",
                )
            }
        }
    }
}

impl StdError for ConcordanceError {}

/// Validates that a set of STH bundles meets the multi-log policy.
pub fn verify_concordance(
    bundles: &[SthBundle],
    policy: &MultiLogPolicy,
) -> Result<Concordance, ConcordanceError> {
    if bundles.is_empty() {
        return Err(ConcordanceError::EmptyInput);
    }
    if !policy.agreement_ratio.is_finite()
        || policy.agreement_ratio < 0.0
        || policy.agreement_ratio > 1.0
    {
        return Err(ConcordanceError::InvalidAgreementRatio(
            policy.agreement_ratio,
        ));
    }

    let total_logs = bundles.len();
    if total_logs < policy.min_logs {
        return Err(ConcordanceError::InsufficientLogs {
            required: policy.min_logs,
            found: total_logs,
        });
    }

    let mut seen_logs: HashSet<&Vec<u8>> = HashSet::with_capacity(total_logs);
    for bundle in bundles {
        if !seen_logs.insert(&bundle.log_id) {
            return Err(ConcordanceError::DuplicateLogId(bundle.log_id.clone()));
        }
        let unique_witnesses: HashSet<&Vec<u8>> = bundle.witness_signatures.iter().collect();
        if unique_witnesses.len() < policy.witness_threshold {
            return Err(ConcordanceError::InsufficientWitnesses {
                log_id: bundle.log_id.clone(),
                found: unique_witnesses.len(),
                required: policy.witness_threshold,
            });
        }
    }

    let required = policy.required_agreement(total_logs);

    let mut clusters: BTreeMap<([u8; 32], u64), Vec<&SthBundle>> = BTreeMap::new();
    for bundle in bundles {
        clusters
            .entry((bundle.root_hash, bundle.tree_size))
            .or_default()
            .push(bundle);
    }

    let mut best_cluster: Option<Concordance> = None;
    let mut best_size = 0usize;

    for ((root_hash, tree_size), group) in clusters {
        let size = group.len();
        if size < best_size {
            continue;
        }
        let logs = group
            .iter()
            .map(|bundle| bundle.log_id.clone())
            .collect::<Vec<_>>();
        if size > best_size || best_cluster.is_none() {
            best_size = size;
            best_cluster = Some(Concordance {
                root_hash,
                tree_size,
                logs,
            });
        }
    }

    let best = best_cluster.ok_or(ConcordanceError::EmptyInput)?;

    if best.logs.len() < required {
        return Err(ConcordanceError::NoAgreement {
            required,
            best: best.logs.len(),
        });
    }

    Ok(best)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_bundle(
        log_id: &[u8],
        root: [u8; 32],
        tree_size: u64,
        witnesses: &[&[u8]],
    ) -> SthBundle {
        SthBundle {
            log_id: log_id.to_vec(),
            root_hash: root,
            tree_size,
            sth_time: 1,
            log_signature: vec![0u8; 48],
            witness_signatures: witnesses.iter().map(|w| w.to_vec()).collect(),
        }
    }

    #[test]
    fn three_logs_agree() {
        let root = [1u8; 32];
        let policy = MultiLogPolicy {
            witness_threshold: 2,
            min_logs: 2,
            agreement_ratio: 0.6,
        };
        let bundles = vec![
            make_bundle(b"log-a", root, 42, &[b"wit1", b"wit2"]),
            make_bundle(b"log-b", root, 42, &[b"wit1", b"wit3"]),
            make_bundle(b"log-c", root, 42, &[b"wit2", b"wit3"]),
        ];

        let concordance = verify_concordance(&bundles, &policy).expect("expected agreement");
        assert_eq!(concordance.root_hash, root);
        assert_eq!(concordance.tree_size, 42);
        assert_eq!(concordance.logs.len(), 3);
        for log_id in [b"log-a", b"log-b", b"log-c"] {
            assert!(concordance.logs.contains(&log_id.to_vec()));
        }
    }

    #[test]
    fn one_log_diverges() {
        let shared_root = [2u8; 32];
        let diverging_root = [3u8; 32];
        let policy = MultiLogPolicy {
            witness_threshold: 1,
            min_logs: 3,
            agreement_ratio: 0.75,
        };
        let bundles = vec![
            make_bundle(b"log-a", shared_root, 64, &[b"wit1"]),
            make_bundle(b"log-b", shared_root, 64, &[b"wit2"]),
            make_bundle(b"log-c", shared_root, 64, &[b"wit3"]),
            make_bundle(b"log-d", diverging_root, 65, &[b"wit4"]),
        ];

        let concordance = verify_concordance(&bundles, &policy).expect("expected 3-of-4 agreement");
        assert_eq!(concordance.root_hash, shared_root);
        assert_eq!(concordance.tree_size, 64);
        assert_eq!(concordance.logs.len(), 3);
        assert!(concordance.logs.contains(&b"log-a".to_vec()));
        assert!(concordance.logs.contains(&b"log-b".to_vec()));
        assert!(concordance.logs.contains(&b"log-c".to_vec()));
        assert!(!concordance.logs.contains(&b"log-d".to_vec()));
    }

    #[test]
    fn all_logs_diverge() {
        let policy = MultiLogPolicy {
            witness_threshold: 1,
            min_logs: 2,
            agreement_ratio: 0.67,
        };
        let bundles = vec![
            make_bundle(b"log-a", [10u8; 32], 5, &[b"wit1"]),
            make_bundle(b"log-b", [11u8; 32], 5, &[b"wit2"]),
            make_bundle(b"log-c", [12u8; 32], 5, &[b"wit3"]),
        ];

        let err = verify_concordance(&bundles, &policy).expect_err("expected disagreement");
        assert!(matches!(
            err,
            ConcordanceError::NoAgreement {
                required: _,
                best: _
            }
        ));
    }
}
