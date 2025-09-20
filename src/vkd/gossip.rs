#![allow(clippy::module_name_repetitions)]

use std::collections::HashSet;
use std::convert::TryInto;
use std::error::Error as StdError;
use std::fmt;

use blstrs::{G1Affine, G1Projective};
use group::prime::PrimeCurveAffine;
use hex::encode as hex_encode;
use libipld::cid::Cid;
use serde::{Deserialize, Serialize};

use crate::quorum::{bls_verify, SIG_DST};
use crate::vkd::VkdTrustAnchors;

/// Gossip payload advertising a new signed tree head from a VKD log.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SthAnnouncement {
    pub sth_cid: Cid,
    pub log_id: Vec<u8>,
    pub root_hash: [u8; 32],
    pub tree_size: u64,
    pub sth_time: u64,
    pub log_signature: Vec<u8>,
    pub witness_signatures: Vec<Vec<u8>>,
}

/// Errors surfaced while validating a gossiped STH announcement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SthValidationError {
    LogIdMismatch { expected: Vec<u8>, found: Vec<u8> },
    MalformedLogSignature,
    InvalidLogSignature,
    InsufficientWitnesses { required: usize, found: usize },
}

impl fmt::Display for SthValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LogIdMismatch { expected, found } => {
                write!(
                    f,
                    "unexpected log id {} (expected {})",
                    hex_encode(found),
                    hex_encode(expected)
                )
            }
            Self::MalformedLogSignature => write!(f, "log signature encoding is invalid"),
            Self::InvalidLogSignature => {
                write!(f, "log signature rejected for advertised STH tuple")
            }
            Self::InsufficientWitnesses { required, found } => {
                write!(
                    f,
                    "only {found} witness signatures verified (requires {required})"
                )
            }
        }
    }
}

impl StdError for SthValidationError {}

/// Validates a gossiped announcement against trusted VKD quorum parameters.
pub fn verify_sth_announcement(
    announcement: &SthAnnouncement,
    trust: &VkdTrustAnchors,
) -> Result<(), SthValidationError> {
    if announcement.log_id != trust.log_id() {
        return Err(SthValidationError::LogIdMismatch {
            expected: trust.log_id().to_vec(),
            found: announcement.log_id.clone(),
        });
    }

    let mut sth_tuple = Vec::new();
    sth_tuple.extend_from_slice(&announcement.root_hash);
    sth_tuple.extend_from_slice(&announcement.tree_size.to_le_bytes());
    sth_tuple.extend_from_slice(&announcement.sth_time.to_le_bytes());
    sth_tuple.extend_from_slice(&announcement.log_id);

    let sth_sig = g1_from_bytes(&announcement.log_signature)
        .ok_or(SthValidationError::MalformedLogSignature)?;
    if !bls_verify(trust.log_public_key(), &sth_tuple, &sth_sig, SIG_DST) {
        return Err(SthValidationError::InvalidLogSignature);
    }

    let mut matched = HashSet::new();
    for sig_bytes in &announcement.witness_signatures {
        if let Some(sig) = g1_from_bytes(sig_bytes) {
            for (index, pk) in trust.witness_public_keys().iter().enumerate() {
                if matched.contains(&index) {
                    continue;
                }
                if bls_verify(pk, &sth_tuple, &sig, SIG_DST) {
                    matched.insert(index);
                    break;
                }
            }
        }
    }

    if matched.len() < trust.witness_threshold() {
        return Err(SthValidationError::InsufficientWitnesses {
            required: trust.witness_threshold(),
            found: matched.len(),
        });
    }

    Ok(())
}

fn g1_from_bytes(bytes: &[u8]) -> Option<G1Projective> {
    let arr: [u8; 48] = bytes.try_into().ok()?;
    let affine = G1Affine::from_compressed(&arr);
    let affine: G1Affine = Option::<G1Affine>::from(affine)?;
    if bool::from(affine.is_identity()) {
        None
    } else {
        Some(G1Projective::from(affine))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blstrs::{G1Projective, G2Projective, Scalar};
    use group::{Curve, Group};
    use multihash::{Code, MultihashDigest};

    use crate::quorum::{bls_sign, SIG_DST};
    use crate::vkd::VkdTrustAnchors;

    fn sample_trust() -> (VkdTrustAnchors, Scalar, Scalar) {
        let log_sk = Scalar::from(42u64);
        let witness_sk = Scalar::from(43u64);
        let log_pk = G2Projective::generator() * log_sk;
        let witness_pk = G2Projective::generator() * witness_sk;
        let trust = VkdTrustAnchors::new(b"testlog".to_vec(), log_pk, vec![witness_pk], 1, log_pk)
            .expect("valid trust anchors");
        (trust, log_sk, witness_sk)
    }

    fn sample_announcement(
        trust: &VkdTrustAnchors,
        log_sk: &Scalar,
        witness_sk: &Scalar,
    ) -> SthAnnouncement {
        let log_id = trust.log_id().to_vec();
        let root_hash = [7u8; 32];
        let tree_size = 8u64;
        let sth_time = 9u64;
        let mut tuple = Vec::new();
        tuple.extend_from_slice(&root_hash);
        tuple.extend_from_slice(&tree_size.to_le_bytes());
        tuple.extend_from_slice(&sth_time.to_le_bytes());
        tuple.extend_from_slice(&log_id);

        let log_sig = bls_sign(log_sk, &tuple, SIG_DST);
        let witness_sig = bls_sign(witness_sk, &tuple, SIG_DST);

        let cid = libipld::cid::Cid::new_v1(
            u64::from(libipld::cbor::DagCborCodec),
            Code::Sha2_256.digest(b"sth"),
        );

        SthAnnouncement {
            sth_cid: cid,
            log_id,
            root_hash,
            tree_size,
            sth_time,
            log_signature: log_sig.to_affine().to_compressed().to_vec(),
            witness_signatures: vec![witness_sig.to_affine().to_compressed().to_vec()],
        }
    }

    #[test]
    fn accepts_valid_announcement() {
        let (trust, log_sk, witness_sk) = sample_trust();
        let announcement = sample_announcement(&trust, &log_sk, &witness_sk);
        assert!(verify_sth_announcement(&announcement, &trust).is_ok());
    }

    #[test]
    fn rejects_bad_log_signature() {
        let (trust, log_sk, witness_sk) = sample_trust();
        let mut announcement = sample_announcement(&trust, &log_sk, &witness_sk);
        announcement.log_signature = G1Projective::identity()
            .to_affine()
            .to_compressed()
            .to_vec();
        let err = verify_sth_announcement(&announcement, &trust)
            .expect_err("invalid signature must be rejected");
        assert!(matches!(err, SthValidationError::MalformedLogSignature));
    }

    #[test]
    fn rejects_insufficient_witnesses() {
        let (trust, log_sk, witness_sk) = sample_trust();
        let mut announcement = sample_announcement(&trust, &log_sk, &witness_sk);
        announcement.witness_signatures.clear();
        let err = verify_sth_announcement(&announcement, &trust)
            .expect_err("missing witnesses must be rejected");
        assert!(matches!(
            err,
            SthValidationError::InsufficientWitnesses { found: 0, .. }
        ));
    }

    #[test]
    fn rejects_wrong_log_id() {
        let (trust, log_sk, witness_sk) = sample_trust();
        let mut announcement = sample_announcement(&trust, &log_sk, &witness_sk);
        announcement.log_id = vec![0xFF];
        let err = verify_sth_announcement(&announcement, &trust)
            .expect_err("mismatched log id must be rejected");
        assert!(matches!(err, SthValidationError::LogIdMismatch { .. }));
    }
}
