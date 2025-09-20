#![forbid(unsafe_code)]

use blstrs::{G1Affine, G1Projective, G2Affine, G2Projective};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::quorum::bls_verify;

const SUPPORTED_VERSION: u32 = 1;
pub(crate) const CONFIG_SIGNATURE_DST: &[u8] = b"CHHAYA_VKD_CONFIG_V1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VkdTrustAnchors {
    log_id: Vec<u8>,
    log_pk: G2Projective,
    witness_pks: Vec<G2Projective>,
    witness_threshold: usize,
    vrf_pk: G2Projective,
}

impl VkdTrustAnchors {
    pub fn new(
        log_id: Vec<u8>,
        log_pk: G2Projective,
        witness_pks: Vec<G2Projective>,
        witness_threshold: usize,
        vrf_pk: G2Projective,
    ) -> Result<Self, VkdConfigError> {
        if log_id.is_empty() {
            return Err(VkdConfigError::EmptyLogId);
        }
        if witness_threshold > witness_pks.len() {
            return Err(VkdConfigError::InvalidWitnessThreshold {
                threshold: witness_threshold,
                total: witness_pks.len(),
            });
        }
        Ok(Self {
            log_id,
            log_pk,
            witness_pks,
            witness_threshold,
            vrf_pk,
        })
    }

    #[must_use]
    pub fn log_id(&self) -> &[u8] {
        &self.log_id
    }

    #[must_use]
    pub fn log_public_key(&self) -> &G2Projective {
        &self.log_pk
    }

    #[must_use]
    pub fn witness_public_keys(&self) -> &[G2Projective] {
        &self.witness_pks
    }

    #[must_use]
    pub fn witness_threshold(&self) -> usize {
        self.witness_threshold
    }

    #[must_use]
    pub fn vrf_public_key(&self) -> &G2Projective {
        &self.vrf_pk
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VkdConfig {
    pub version: u32,
    pub log_id: String,
    pub log_public_key: String,
    pub witness_public_keys: Vec<String>,
    pub witness_threshold: usize,
    pub vrf_public_key: String,
}

impl VkdConfig {
    fn signing_message(&self) -> Result<Vec<u8>, VkdConfigError> {
        serde_json::to_vec(self).map_err(VkdConfigError::Serialize)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedVkdConfig {
    pub config: VkdConfig,
    pub signature: String,
}

#[derive(Debug, Error)]
pub enum VkdConfigError {
    #[error("unsupported VKD config version {version}")]
    UnsupportedVersion { version: u32 },
    #[error("log identifier must not be empty")]
    EmptyLogId,
    #[error("invalid log identifier encoding")]
    InvalidLogIdEncoding,
    #[error("invalid log public key encoding")]
    InvalidLogPublicKey,
    #[error("invalid witness public key encoding at index {index}")]
    InvalidWitnessPublicKey { index: usize },
    #[error("invalid witness signature threshold {threshold} for {total} keys")]
    InvalidWitnessThreshold { threshold: usize, total: usize },
    #[error("invalid VRF public key encoding")]
    InvalidVrfPublicKey,
    #[error("invalid configuration signature encoding")]
    InvalidSignatureEncoding,
    #[error("configuration signature rejected")]
    InvalidSignature,
    #[error("failed to serialize VKD config: {0}")]
    Serialize(serde_json::Error),
}

impl SignedVkdConfig {
    pub fn verify(&self, signer_pk: &G2Projective) -> Result<VkdTrustAnchors, VkdConfigError> {
        if self.config.version != SUPPORTED_VERSION {
            return Err(VkdConfigError::UnsupportedVersion {
                version: self.config.version,
            });
        }

        let message = self.config.signing_message()?;
        let signature =
            decode_g1(&self.signature).ok_or(VkdConfigError::InvalidSignatureEncoding)?;
        if !bls_verify(signer_pk, &message, &signature, CONFIG_SIGNATURE_DST) {
            return Err(VkdConfigError::InvalidSignature);
        }

        let log_id =
            hex::decode(&self.config.log_id).map_err(|_| VkdConfigError::InvalidLogIdEncoding)?;
        if log_id.is_empty() {
            return Err(VkdConfigError::EmptyLogId);
        }

        let log_pk =
            decode_g2(&self.config.log_public_key).ok_or(VkdConfigError::InvalidLogPublicKey)?;

        let mut witness_pks = Vec::with_capacity(self.config.witness_public_keys.len());
        for (index, pk_hex) in self.config.witness_public_keys.iter().enumerate() {
            let pk = decode_g2(pk_hex).ok_or(VkdConfigError::InvalidWitnessPublicKey { index })?;
            witness_pks.push(pk);
        }

        let vrf_pk =
            decode_g2(&self.config.vrf_public_key).ok_or(VkdConfigError::InvalidVrfPublicKey)?;

        VkdTrustAnchors::new(
            log_id,
            log_pk,
            witness_pks,
            self.config.witness_threshold,
            vrf_pk,
        )
    }
}

fn decode_g2(hex: &str) -> Option<G2Projective> {
    let bytes = hex::decode(hex).ok()?;
    if bytes.len() != 96 {
        return None;
    }
    let mut buf = [0u8; 96];
    buf.copy_from_slice(&bytes);
    let affine = G2Affine::from_compressed(&buf).into_option()?;
    Some(G2Projective::from(&affine))
}

fn decode_g1(hex: &str) -> Option<G1Projective> {
    let bytes = hex::decode(hex).ok()?;
    if bytes.len() != 48 {
        return None;
    }
    let mut buf = [0u8; 48];
    buf.copy_from_slice(&bytes);
    let affine = G1Affine::from_compressed(&buf).into_option()?;
    Some(G1Projective::from(&affine))
}

#[cfg(test)]
mod tests {
    use super::*;
    use blstrs::{G2Projective, Scalar};
    use group::{Curve, Group};

    fn sample_config() -> (SignedVkdConfig, G2Projective, Scalar) {
        let log_sk = Scalar::from(42u64);
        let witness_sk = Scalar::from(43u64);
        let signer_sk = Scalar::from(44u64);
        let log_pk = G2Projective::generator() * log_sk;
        let witness_pk = G2Projective::generator() * witness_sk;
        let signer_pk = G2Projective::generator() * signer_sk;

        let config = VkdConfig {
            version: SUPPORTED_VERSION,
            log_id: hex::encode(b"testlog"),
            log_public_key: hex::encode(log_pk.to_affine().to_compressed()),
            witness_public_keys: vec![hex::encode(witness_pk.to_affine().to_compressed())],
            witness_threshold: 1,
            vrf_public_key: hex::encode(log_pk.to_affine().to_compressed()),
        };
        let message = config.signing_message().expect("message");
        let signature = crate::quorum::bls_sign(&signer_sk, &message, CONFIG_SIGNATURE_DST);
        let signed = SignedVkdConfig {
            config,
            signature: hex::encode(signature.to_affine().to_compressed()),
        };
        (signed, signer_pk, log_sk)
    }

    #[test]
    fn verifies_signed_config() {
        let (signed, signer_pk, _) = sample_config();
        let anchors = signed.verify(&signer_pk).expect("anchors");
        assert_eq!(anchors.log_id(), b"testlog");
        assert_eq!(anchors.witness_threshold(), 1);
        assert_eq!(anchors.witness_public_keys().len(), 1);
    }

    #[test]
    fn rejects_invalid_signature() {
        let (mut signed, signer_pk, _) = sample_config();
        signed.signature = "00".repeat(48);
        assert!(matches!(
            signed.verify(&signer_pk),
            Err(VkdConfigError::InvalidSignatureEncoding)
        ));
    }

    #[test]
    fn detects_signature_mismatch() {
        let (signed, _signer_pk, log_sk) = sample_config();
        let other_pk = G2Projective::generator() * (log_sk + Scalar::from(1u64));
        assert!(matches!(
            signed.verify(&other_pk),
            Err(VkdConfigError::InvalidSignature)
        ));
    }
}
