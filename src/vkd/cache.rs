#![forbid(unsafe_code)]

use std::collections::{hash_map::Entry, HashMap};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use blstrs::G2Projective;
use libipld::{
    cbor::DagCborCodec,
    cid::Cid,
    codec::Codec,
    serde::{from_ipld, to_ipld},
};
use multihash::{Code, MultihashDigest};
use thiserror::Error;

use crate::{verify_vkd_proof, VerifiedSth, VkdProof};

/// Errors produced while persisting or validating queued VKD proofs.
#[derive(Debug, Error)]
pub enum ProofQueueError {
    #[error("proof bundle {cid} already seen")]
    Duplicate { cid: Cid },
    #[error("failed to create directory {path}: {source}")]
    CreateDir {
        path: Arc<PathBuf>,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write proof {cid} to {path}: {source}")]
    Write {
        cid: Cid,
        path: Arc<PathBuf>,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read directory {path}: {source}")]
    ReadDir {
        path: Arc<PathBuf>,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to inspect file metadata for {path}: {source}")]
    Metadata {
        path: Arc<PathBuf>,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read proof data at {path}: {source}")]
    Read {
        path: Arc<PathBuf>,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to encode proof bundle: {message}")]
    Encode { message: String },
    #[error("failed to decode proof from {path}: {error}")]
    Decode { path: Arc<PathBuf>, error: String },
    #[error("invalid CID in file name at {path}: {reason}")]
    InvalidCid { path: Arc<PathBuf>, reason: String },
    #[error("proof bundle {cid} rejected during verification")]
    Verification { cid: Cid },
    #[error("failed to move proof {cid} to accepted directory: {source}")]
    Move {
        cid: Cid,
        #[source]
        source: std::io::Error,
    },
}

/// Reasons a pending proof bundle was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProofRejection {
    Decode(String),
    Verification,
}

/// Outcome of verifying a proof pulled from the queue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProofProcessingResult {
    Accepted { cid: Cid, verified: VerifiedSth },
    Rejected { cid: Cid, reason: ProofRejection },
}

/// Disk-backed queue for deduplicating and verifying VKD proof bundles.
#[derive(Clone, Debug)]
pub struct ProofQueue {
    root: PathBuf,
    pending_dir: PathBuf,
    accepted_dir: PathBuf,
}

impl ProofQueue {
    pub fn new<P: AsRef<Path>>(root: P) -> Result<Self, ProofQueueError> {
        let root = root.as_ref().to_path_buf();
        let pending_dir = root.join("pending");
        let accepted_dir = root.join("accepted");
        fs::create_dir_all(&pending_dir).map_err(|source| ProofQueueError::CreateDir {
            path: Arc::new(pending_dir.clone()),
            source,
        })?;
        fs::create_dir_all(&accepted_dir).map_err(|source| ProofQueueError::CreateDir {
            path: Arc::new(accepted_dir.clone()),
            source,
        })?;
        Ok(Self {
            root,
            pending_dir,
            accepted_dir,
        })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn enqueue(&self, proof: &VkdProof) -> Result<Cid, ProofQueueError> {
        let (cid, bytes) = encode_proof(proof)?;
        if self.has_seen(&cid) {
            return Err(ProofQueueError::Duplicate { cid });
        }
        let path = self.pending_path(&cid);
        let path_arc = Arc::new(path.clone());
        let mut file = OpenOptions::new();
        file.write(true).create_new(true);
        let mut handle = file.open(&path).map_err(|source| {
            if source.kind() == std::io::ErrorKind::AlreadyExists {
                ProofQueueError::Duplicate { cid }
            } else {
                ProofQueueError::Write {
                    cid,
                    path: path_arc.clone(),
                    source,
                }
            }
        })?;
        handle
            .write_all(&bytes)
            .map_err(|source| ProofQueueError::Write {
                cid,
                path: path_arc.clone(),
                source,
            })?;
        handle.sync_all().map_err(|source| ProofQueueError::Write {
            cid,
            path: path_arc,
            source,
        })?;
        Ok(cid)
    }

    pub fn process_pending(
        &self,
        expected_log_id: &[u8],
        log_pk: &G2Projective,
        witness_pks: &[G2Projective],
        witness_threshold: usize,
        vrf_pk: &G2Projective,
    ) -> Result<Vec<ProofProcessingResult>, ProofQueueError> {
        let mut last_verified = self.load_last_verified()?;
        let mut results = Vec::new();
        for (cid, path) in collect_entries(&self.pending_dir)? {
            let proof = match read_proof(&path) {
                Ok(proof) => proof,
                Err(ProofQueueError::Decode { error, .. }) => {
                    results.push(ProofProcessingResult::Rejected {
                        cid,
                        reason: ProofRejection::Decode(error),
                    });
                    continue;
                }
                Err(other) => return Err(other),
            };
            let prev = last_verified.get(&proof.log_id).cloned();
            match verify_vkd_proof(
                &proof,
                expected_log_id,
                log_pk,
                witness_pks,
                witness_threshold,
                vrf_pk,
                prev,
            ) {
                Some(verified) => {
                    let dest = self.accepted_path(&cid);
                    fs::rename(&path, &dest)
                        .map_err(|source| ProofQueueError::Move { cid, source })?;
                    last_verified.insert(proof.log_id.clone(), verified.clone());
                    results.push(ProofProcessingResult::Accepted { cid, verified });
                }
                None => {
                    results.push(ProofProcessingResult::Rejected {
                        cid,
                        reason: ProofRejection::Verification,
                    });
                }
            }
        }
        Ok(results)
    }

    fn load_last_verified(&self) -> Result<HashMap<Vec<u8>, VerifiedSth>, ProofQueueError> {
        let mut map = HashMap::new();
        for (_cid, path) in collect_entries(&self.accepted_dir)? {
            let proof = read_proof(&path)?;
            let verified = VerifiedSth {
                root_hash: proof.sth_root_hash,
                tree_size: proof.sth_tree_size,
                sth_time: proof.sth_time,
                log_id: proof.log_id.clone(),
            };
            match map.entry(proof.log_id.clone()) {
                Entry::Vacant(entry) => {
                    entry.insert(verified);
                }
                Entry::Occupied(mut entry) => {
                    let current = entry.get();
                    if verified.tree_size > current.tree_size
                        || (verified.tree_size == current.tree_size
                            && verified.sth_time > current.sth_time)
                    {
                        entry.insert(verified);
                    }
                }
            }
        }
        Ok(map)
    }

    fn has_seen(&self, cid: &Cid) -> bool {
        self.pending_path(cid).exists() || self.accepted_path(cid).exists()
    }

    fn pending_path(&self, cid: &Cid) -> PathBuf {
        self.pending_dir.join(cid.to_string())
    }

    fn accepted_path(&self, cid: &Cid) -> PathBuf {
        self.accepted_dir.join(cid.to_string())
    }
}

fn encode_proof(proof: &VkdProof) -> Result<(Cid, Vec<u8>), ProofQueueError> {
    let ipld = to_ipld(proof).map_err(|err| ProofQueueError::Encode {
        message: err.to_string(),
    })?;
    let bytes = DagCborCodec
        .encode(&ipld)
        .map_err(|err| ProofQueueError::Encode {
            message: err.to_string(),
        })?;
    let cid = Cid::new_v1(u64::from(DagCborCodec), Code::Sha2_256.digest(&bytes));
    Ok((cid, bytes))
}

fn read_proof(path: &Path) -> Result<VkdProof, ProofQueueError> {
    let path_buf = Arc::new(path.to_path_buf());
    let data = fs::read(path).map_err(|source| ProofQueueError::Read {
        path: path_buf.clone(),
        source,
    })?;
    let ipld = DagCborCodec
        .decode(&data)
        .map_err(|err| ProofQueueError::Decode {
            path: path_buf.clone(),
            error: err.to_string(),
        })?;
    from_ipld(ipld).map_err(|err| ProofQueueError::Decode {
        path: path_buf,
        error: err.to_string(),
    })
}

fn collect_entries(dir: &Path) -> Result<Vec<(Cid, PathBuf)>, ProofQueueError> {
    let mut entries = Vec::new();
    let dir_path = Arc::new(dir.to_path_buf());
    let read_dir = fs::read_dir(dir).map_err(|source| ProofQueueError::ReadDir {
        path: dir_path.clone(),
        source,
    })?;
    for entry in read_dir {
        let entry = entry.map_err(|source| ProofQueueError::ReadDir {
            path: dir_path.clone(),
            source,
        })?;
        let entry_path = entry.path();
        let entry_arc = Arc::new(entry_path.clone());
        let metadata = entry
            .metadata()
            .map_err(|source| ProofQueueError::Metadata {
                path: entry_arc.clone(),
                source,
            })?;
        if !metadata.is_file() {
            continue;
        }
        let path = entry_path;
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            return Err(ProofQueueError::InvalidCid {
                path: entry_arc.clone(),
                reason: "non-utf8 file name".to_string(),
            });
        };
        let cid = Cid::try_from(name_str).map_err(|err| ProofQueueError::InvalidCid {
            path: entry_arc,
            reason: err.to_string(),
        })?;
        entries.push((cid, path));
    }
    entries.sort_by(|(_, a_path), (_, b_path)| a_path.cmp(b_path));
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::TransparencyLog;
    use crate::quorum::{bls_sign, SIG_DST};
    use blstrs::Scalar;
    use group::{Curve, Group};
    use libipld::multihash::MultihashDigest;
    use tempfile::tempdir;

    const LOG_ID: &[u8] = b"testlog";

    fn sample_proof() -> VkdProof {
        let log_sk = Scalar::from(42u64);
        let witness_sk = Scalar::from(43u64);
        let leaf = [7u8; 32];
        let mut log = TransparencyLog::new();
        log.append(leaf).expect("append leaf");
        let proof = log.prove(0).expect("prove leaf");
        let root = log.root();
        let tree_size = 1u64;
        let sth_time = 9u64;

        let mut tuple = Vec::new();
        tuple.extend_from_slice(&root);
        tuple.extend_from_slice(&tree_size.to_le_bytes());
        tuple.extend_from_slice(&sth_time.to_le_bytes());
        tuple.extend_from_slice(LOG_ID);

        let sth_sig = bls_sign(&log_sk, &tuple, SIG_DST)
            .to_affine()
            .to_compressed()
            .to_vec();
        let witness_sig = bls_sign(&witness_sk, &tuple, SIG_DST)
            .to_affine()
            .to_compressed()
            .to_vec();
        let vrf_sig = bls_sign(&log_sk, &leaf, SIG_DST)
            .to_affine()
            .to_compressed()
            .to_vec();

        let bundle_cid = Cid::new_v1(u64::from(DagCborCodec), Code::Sha2_256.digest(b"bundle"));
        let quorum_desc_cid =
            Cid::new_v1(u64::from(DagCborCodec), Code::Sha2_256.digest(b"quorum"));

        VkdProof {
            log_id: LOG_ID.to_vec(),
            sth_root_hash: root,
            sth_tree_size: tree_size,
            sth_time,
            sth_sig,
            witness_sigs: vec![witness_sig],
            inclusion_hash: leaf,
            inclusion_proof: proof,
            consistency_proof: None,
            vrf_proof: vrf_sig,
            bundle_cid,
            quorum_desc_cid,
        }
    }

    fn verifier_params() -> (G2Projective, Vec<G2Projective>, usize) {
        let log_pk = G2Projective::generator() * Scalar::from(42u64);
        let witness_pk = G2Projective::generator() * Scalar::from(43u64);
        (log_pk, vec![witness_pk], 1)
    }

    #[test]
    fn enqueue_rejects_duplicates() {
        let temp = tempdir().expect("tempdir");
        let queue = ProofQueue::new(temp.path()).expect("queue");
        let proof = sample_proof();
        let cid = queue.enqueue(&proof).expect("enqueue");
        let pending = temp.path().join("pending").join(cid.to_string());
        assert!(pending.exists());
        let err = queue.enqueue(&proof).expect_err("duplicate allowed");
        assert!(matches!(err, ProofQueueError::Duplicate { .. }));
    }

    #[test]
    fn process_moves_verified_proofs() {
        let temp = tempdir().expect("tempdir");
        let queue = ProofQueue::new(temp.path()).expect("queue");
        let proof = sample_proof();
        let cid = queue.enqueue(&proof).expect("enqueue");
        let (log_pk, witness_pks, witness_threshold) = verifier_params();
        let results = queue
            .process_pending(LOG_ID, &log_pk, &witness_pks, witness_threshold, &log_pk)
            .expect("process");
        assert_eq!(results.len(), 1);
        match &results[0] {
            ProofProcessingResult::Accepted { cid: accepted, .. } => {
                assert_eq!(accepted, &cid);
            }
            other => panic!("unexpected result {other:?}"),
        }
        let pending = temp.path().join("pending").join(cid.to_string());
        let accepted = temp.path().join("accepted").join(cid.to_string());
        assert!(!pending.exists());
        assert!(accepted.exists());
        let err = queue
            .enqueue(&proof)
            .expect_err("accepted duplicate allowed");
        assert!(matches!(err, ProofQueueError::Duplicate { .. }));
    }

    #[test]
    fn process_rejects_invalid_proofs() {
        let temp = tempdir().expect("tempdir");
        let queue = ProofQueue::new(temp.path()).expect("queue");
        let mut proof = sample_proof();
        let cid_valid = queue.enqueue(&proof).expect("enqueue valid");
        let pending_path = temp.path().join("pending").join(cid_valid.to_string());
        let mut data = fs::read(&pending_path).expect("read");
        data[0] ^= 0xAA;
        fs::write(&pending_path, &data).expect("write tampered");
        let (log_pk, witness_pks, witness_threshold) = verifier_params();
        let results = queue
            .process_pending(LOG_ID, &log_pk, &witness_pks, witness_threshold, &log_pk)
            .expect("process");
        assert_eq!(results.len(), 1);
        assert!(matches!(
            &results[0],
            ProofProcessingResult::Rejected {
                cid,
                reason: ProofRejection::Decode(_)
            } if cid == &cid_valid
        ));
        assert!(pending_path.exists());

        proof.sth_sig[0] ^= 0x55;
        let cid_invalid = queue.enqueue(&proof).expect("enqueue invalid");
        let results = queue
            .process_pending(LOG_ID, &log_pk, &witness_pks, witness_threshold, &log_pk)
            .expect("process invalid");
        assert_eq!(results.len(), 2);
        assert!(results.iter().any(|entry| matches!(
            entry,
            ProofProcessingResult::Rejected {
                cid,
                reason: ProofRejection::Decode(_)
            } if cid == &cid_valid
        )));
        assert!(results.iter().any(|entry| matches!(
            entry,
            ProofProcessingResult::Rejected {
                cid,
                reason: ProofRejection::Verification
            } if cid == &cid_invalid
        )));
        let pending_invalid = temp.path().join("pending").join(cid_invalid.to_string());
        assert!(pending_invalid.exists());
    }
}
