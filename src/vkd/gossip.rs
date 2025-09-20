#![allow(clippy::module_name_repetitions)]

use std::collections::HashSet;
use std::convert::TryInto;
use std::error::Error as StdError;
use std::fmt;

use blstrs::{G1Affine, G1Projective, G2Projective};
use group::prime::PrimeCurveAffine;
use hex::encode as hex_encode;
use libipld::cid::Cid;
use serde::{Deserialize, Serialize};

use crate::quorum::{bls_verify, SIG_DST};

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
    expected_log_id: &[u8],
    log_pk: &G2Projective,
    witness_pks: &[G2Projective],
    witness_threshold: usize,
) -> Result<(), SthValidationError> {
    if announcement.log_id != expected_log_id {
        return Err(SthValidationError::LogIdMismatch {
            expected: expected_log_id.to_vec(),
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
    if !bls_verify(log_pk, &sth_tuple, &sth_sig, SIG_DST) {
        return Err(SthValidationError::InvalidLogSignature);
    }

    let mut matched = HashSet::new();
    for sig_bytes in &announcement.witness_signatures {
        if let Some(sig) = g1_from_bytes(sig_bytes) {
            for (index, pk) in witness_pks.iter().enumerate() {
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

    if matched.len() < witness_threshold {
        return Err(SthValidationError::InsufficientWitnesses {
            required: witness_threshold,
            found: matched.len(),
        });
    }

    Ok(())
}

#[must_use]
/// Returns the default log identifier trusted by the client.
pub fn default_sth_log_id() -> &'static [u8] {
    crate::VKD_LOG_ID
}

#[must_use]
/// Returns the static public key used to verify STH signatures in tests.
pub fn default_sth_log_public_key() -> G2Projective {
    crate::vkd_log_pk()
}

#[must_use]
/// Returns the witness public keys used to threshold-sign default STHs.
pub fn default_sth_witness_public_keys() -> Vec<G2Projective> {
    crate::vkd_witness_pks()
}

#[must_use]
/// Returns the witness signature threshold for default STH verification.
pub fn default_sth_witness_threshold() -> usize {
    crate::vkd_witness_threshold()
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

    fn sample_announcement() -> (SthAnnouncement, Vec<G2Projective>) {
        let log_id = default_sth_log_id().to_vec();
        let root_hash = [7u8; 32];
        let tree_size = 8u64;
        let sth_time = 9u64;
        let mut tuple = Vec::new();
        tuple.extend_from_slice(&root_hash);
        tuple.extend_from_slice(&tree_size.to_le_bytes());
        tuple.extend_from_slice(&sth_time.to_le_bytes());
        tuple.extend_from_slice(&log_id);

        let log_sk = Scalar::from(42u64);
        let witness_sk = Scalar::from(43u64);
        let log_sig = bls_sign(&log_sk, &tuple, SIG_DST);
        let witness_sig = bls_sign(&witness_sk, &tuple, SIG_DST);

        let cid = libipld::cid::Cid::new_v1(
            u64::from(libipld::cbor::DagCborCodec),
            Code::Sha2_256.digest(b"sth"),
        );

        let announcement = SthAnnouncement {
            sth_cid: cid,
            log_id,
            root_hash,
            tree_size,
            sth_time,
            log_signature: log_sig.to_affine().to_compressed().to_vec(),
            witness_signatures: vec![witness_sig.to_affine().to_compressed().to_vec()],
        };

        let witness_pks = vec![G2Projective::generator() * witness_sk];

        (announcement, witness_pks)
    }

    #[test]
    fn accepts_valid_announcement() {
        let (announcement, witness_pks) = sample_announcement();
        let log_pk = default_sth_log_public_key();
        assert!(verify_sth_announcement(
            &announcement,
            default_sth_log_id(),
            &log_pk,
            &witness_pks,
            default_sth_witness_threshold(),
        )
        .is_ok());
    }

    #[test]
    fn rejects_bad_log_signature() {
        let (mut announcement, witness_pks) = sample_announcement();
        let log_pk = default_sth_log_public_key();
        announcement.log_signature = G1Projective::identity()
            .to_affine()
            .to_compressed()
            .to_vec();
        let err = verify_sth_announcement(
            &announcement,
            default_sth_log_id(),
            &log_pk,
            &witness_pks,
            default_sth_witness_threshold(),
        )
        .expect_err("invalid signature must be rejected");
        assert!(matches!(err, SthValidationError::MalformedLogSignature));
    }

    #[test]
    fn rejects_insufficient_witnesses() {
        let (announcement, _witness_pks) = sample_announcement();
        let log_pk = default_sth_log_public_key();
        let empty: Vec<G2Projective> = Vec::new();
        let err = verify_sth_announcement(
            &announcement,
            default_sth_log_id(),
            &log_pk,
            &empty,
            default_sth_witness_threshold(),
        )
        .expect_err("missing witnesses must be rejected");
        assert!(matches!(
            err,
            SthValidationError::InsufficientWitnesses { found: 0, .. }
        ));
    }

    #[test]
    fn rejects_wrong_log_id() {
        let (mut announcement, witness_pks) = sample_announcement();
        let log_pk = default_sth_log_public_key();
        announcement.log_id = vec![0xFF];
        let err = verify_sth_announcement(
            &announcement,
            default_sth_log_id(),
            &log_pk,
            &witness_pks,
            default_sth_witness_threshold(),
        )
        .expect_err("mismatched log id must be rejected");
        assert!(matches!(err, SthValidationError::LogIdMismatch { .. }));
    }
}
