#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::quorum::{bls_verify, QuorumDescriptor, QuorumError, SIG_DST};
use blake3::Hasher;
use blstrs::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use ff::PrimeField;
use group::Curve;
use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::fs;

const SUPPORTED_VERSION: u32 = 1;

/// Peer identity and advertised addresses contained in a bootstrap list.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BootstrapPeerRecord {
    pub peer_id: String,
    pub addresses: Vec<String>,
}

/// Signed snapshot of peers published by a bootstrap quorum.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BootstrapList {
    pub version: u32,
    pub published_at: u64,
    pub expires_at: u64,
    pub peers: Vec<BootstrapPeerRecord>,
}

impl BootstrapList {
    pub fn canonicalize(&mut self) {
        for peer in &mut self.peers {
            peer.addresses.sort();
            peer.addresses.dedup();
        }
        self.peers.sort_by(|a, b| a.peer_id.cmp(&b.peer_id));
    }

    fn digest(&self) -> Result<[u8; 32], BootstrapError> {
        let mut hasher = Hasher::new();
        let payload = serde_json::to_vec(self).map_err(BootstrapError::Serialize)?;
        hasher.update(&payload);
        Ok(*hasher.finalize().as_bytes())
    }
}

/// Aggregated BLS signature and participant metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BootstrapSignature {
    pub aggregated: String,
    pub signers: Vec<String>,
}

/// Bundle tying a bootstrap list to the quorum signature that authenticates it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedBootstrapList {
    pub quorum: QuorumDescriptor,
    pub list: BootstrapList,
    pub signature: BootstrapSignature,
}

/// Supported sources for obtaining bootstrap lists.
#[derive(Clone, Debug)]
pub enum BootstrapSource {
    File(PathBuf),
    Inline(SignedBootstrapList),
}

impl From<PathBuf> for BootstrapSource {
    fn from(path: PathBuf) -> Self {
        Self::File(path)
    }
}

/// Local policy describing the trusted bootstrap quorum configuration.
#[derive(Clone, Debug)]
pub struct TrustedBootstrapQuorum {
    pub descriptor: QuorumDescriptor,
    pub public_key: G2Projective,
    pub minimum_signers: usize,
    allowed_signers: Option<HashSet<String>>,
}

impl TrustedBootstrapQuorum {
    pub fn new(
        descriptor: QuorumDescriptor,
        public_key: G2Projective,
        minimum_signers: usize,
        allowed_signers: Option<HashSet<String>>,
    ) -> Self {
        Self {
            descriptor,
            public_key,
            minimum_signers,
            allowed_signers,
        }
    }

    fn allowed_signers(&self) -> Option<&HashSet<String>> {
        self.allowed_signers.as_ref()
    }

    pub fn signing_message(&self, list: &BootstrapList) -> Result<Vec<u8>, BootstrapError> {
        let mut message = Vec::with_capacity(64);
        message.extend_from_slice(&self.descriptor.digest());
        message.extend_from_slice(&list.digest()?);
        Ok(message)
    }
}

/// Configuration file format describing the trusted bootstrap quorum.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QuorumConfig {
    pub descriptor: QuorumDescriptor,
    pub minimum_signers: usize,
    pub public_key: String,
    #[serde(default)]
    pub allowed_signers: Vec<String>,
}

impl QuorumConfig {
    pub fn into_trusted(self) -> Result<TrustedBootstrapQuorum, BootstrapError> {
        let public_key = parse_g2_hex(&self.public_key)?;
        let allowed = if self.allowed_signers.is_empty() {
            None
        } else {
            let mut set = HashSet::new();
            for signer in self.allowed_signers {
                let normalised = normalise_hex(&signer);
                let _ = parse_scalar_hex(&normalised)?;
                set.insert(normalised);
            }
            Some(set)
        };
        Ok(TrustedBootstrapQuorum::new(
            self.descriptor,
            public_key,
            self.minimum_signers,
            allowed,
        ))
    }
}

/// Errors surfaced while loading or validating bootstrap lists.
#[derive(Debug, Error)]
pub enum BootstrapError {
    #[error("failed to read bootstrap list {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse bootstrap list {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to decode bootstrap list: {0}")]
    ParseInline(#[from] serde_json::Error),
    #[error("failed to serialise bootstrap list: {0}")]
    Serialize(serde_json::Error),
    #[error("bootstrap list expired at {expires_at}")]
    Expired { expires_at: u64 },
    #[error("bootstrap list timestamps are inconsistent")]
    InvalidTimestamps,
    #[error("bootstrap list targets unsupported version {version}")]
    UnsupportedVersion { version: u32 },
    #[error("bootstrap quorum descriptor mismatch")]
    QuorumMismatch,
    #[error("aggregated signature encoding is invalid")]
    InvalidSignatureEncoding,
    #[error("aggregated signature failed verification")]
    InvalidSignature,
    #[error("insufficient quorum signatures: required {required}, found {found}")]
    ThresholdNotMet { required: usize, found: usize },
    #[error("duplicate signer {signer}")]
    DuplicateSigner { signer: String },
    #[error("unknown signer {signer}")]
    UnknownSigner { signer: String },
    #[error("invalid signer encoding")]
    InvalidSignerEncoding,
    #[error("invalid quorum public key encoding")]
    InvalidPublicKeyEncoding,
    #[error("invalid peer id {value}")]
    InvalidPeerId { value: String },
    #[error("invalid multiaddr {address} for peer {peer}")]
    InvalidMultiaddr { peer: String, address: String },
    #[error("system time is before the Unix epoch")]
    TimeError,
    #[error("signature aggregation failed")]
    Aggregation,
}

impl From<QuorumError> for BootstrapError {
    fn from(_: QuorumError) -> Self {
        Self::Aggregation
    }
}

/// Loads peers from every source and verifies them against the trusted quorum.
pub async fn collect_bootstrap_peers(
    sources: &[BootstrapSource],
    quorum: &TrustedBootstrapQuorum,
    now: SystemTime,
) -> Result<Vec<(PeerId, Multiaddr)>, BootstrapError> {
    let mut aggregated = Vec::new();
    let mut seen = HashSet::new();

    for source in sources {
        let signed = load_source(source).await?;
        let entries = verify_signed_list(&signed, quorum, now)?;
        for (peer, addr) in entries {
            let key = (peer, addr.clone());
            if seen.insert(key) {
                aggregated.push((peer, addr));
            }
        }
    }

    Ok(aggregated)
}

/// Checks expiry, quorum signature, and address validity for a signed list.
pub fn verify_signed_list(
    signed: &SignedBootstrapList,
    quorum: &TrustedBootstrapQuorum,
    now: SystemTime,
) -> Result<Vec<(PeerId, Multiaddr)>, BootstrapError> {
    if signed.quorum != quorum.descriptor {
        return Err(BootstrapError::QuorumMismatch);
    }

    if signed.list.version != SUPPORTED_VERSION {
        return Err(BootstrapError::UnsupportedVersion {
            version: signed.list.version,
        });
    }

    if signed.list.expires_at <= signed.list.published_at {
        return Err(BootstrapError::InvalidTimestamps);
    }

    let now_secs = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BootstrapError::TimeError)?
        .as_secs();
    if now_secs >= signed.list.expires_at {
        return Err(BootstrapError::Expired {
            expires_at: signed.list.expires_at,
        });
    }

    let mut unique_signers = HashSet::new();
    if signed.signature.signers.len() < quorum.minimum_signers {
        return Err(BootstrapError::ThresholdNotMet {
            required: quorum.minimum_signers,
            found: signed.signature.signers.len(),
        });
    }
    for signer in &signed.signature.signers {
        let normalised = normalise_hex(signer);
        if !unique_signers.insert(normalised.clone()) {
            return Err(BootstrapError::DuplicateSigner {
                signer: signer.clone(),
            });
        }
        parse_scalar_hex(&normalised)?;
        if let Some(allowed) = quorum.allowed_signers() {
            if !allowed.contains(&normalised) {
                return Err(BootstrapError::UnknownSigner {
                    signer: signer.clone(),
                });
            }
        }
    }

    let signature = parse_g1_hex(&signed.signature.aggregated)?;
    let message = quorum.signing_message(&signed.list)?;
    if !bls_verify(&quorum.public_key, &message, &signature, SIG_DST) {
        return Err(BootstrapError::InvalidSignature);
    }

    let mut dedup = HashSet::new();
    let mut peers = Vec::new();
    for record in &signed.list.peers {
        let peer_id =
            PeerId::from_str(&record.peer_id).map_err(|_| BootstrapError::InvalidPeerId {
                value: record.peer_id.clone(),
            })?;

        for addr in &record.addresses {
            let parsed =
                Multiaddr::from_str(addr).map_err(|_| BootstrapError::InvalidMultiaddr {
                    peer: record.peer_id.clone(),
                    address: addr.clone(),
                })?;
            if dedup.insert((peer_id, parsed.clone())) {
                peers.push((peer_id, parsed));
            }
        }
    }

    Ok(peers)
}

/// Serializes a scalar identifier into lowercase hex.
pub fn scalar_to_hex(id: &Scalar) -> String {
    hex::encode(id.to_repr())
}

/// Serializes a BLS signature in compressed form to hex.
pub fn signature_to_hex(signature: &G1Projective) -> String {
    hex::encode(signature.to_affine().to_compressed())
}

async fn load_source(source: &BootstrapSource) -> Result<SignedBootstrapList, BootstrapError> {
    match source {
        BootstrapSource::File(path) => {
            let bytes = fs::read(path).await.map_err(|error| BootstrapError::Read {
                path: path.clone(),
                source: error,
            })?;
            serde_json::from_slice(&bytes).map_err(|error| BootstrapError::Parse {
                path: path.clone(),
                source: error,
            })
        }
        BootstrapSource::Inline(list) => Ok(list.clone()),
    }
}

fn parse_g1_hex(hex: &str) -> Result<G1Projective, BootstrapError> {
    let bytes = hex::decode(hex).map_err(|_| BootstrapError::InvalidSignatureEncoding)?;
    if bytes.len() != 48 {
        return Err(BootstrapError::InvalidSignatureEncoding);
    }
    let mut buf = [0u8; 48];
    buf.copy_from_slice(&bytes);
    let affine = G1Affine::from_compressed(&buf)
        .into_option()
        .ok_or(BootstrapError::InvalidSignatureEncoding)?;
    Ok(G1Projective::from(&affine))
}

fn parse_g2_hex(hex: &str) -> Result<G2Projective, BootstrapError> {
    let bytes = hex::decode(hex).map_err(|_| BootstrapError::InvalidPublicKeyEncoding)?;
    if bytes.len() != 96 {
        return Err(BootstrapError::InvalidPublicKeyEncoding);
    }
    let mut buf = [0u8; 96];
    buf.copy_from_slice(&bytes);
    let affine = G2Affine::from_compressed(&buf)
        .into_option()
        .ok_or(BootstrapError::InvalidPublicKeyEncoding)?;
    Ok(G2Projective::from(&affine))
}

fn parse_scalar_hex(hex: &str) -> Result<Scalar, BootstrapError> {
    let bytes = hex::decode(hex).map_err(|_| BootstrapError::InvalidSignerEncoding)?;
    if bytes.len() != 32 {
        return Err(BootstrapError::InvalidSignerEncoding);
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&bytes);
    Scalar::from_repr(buf)
        .into_option()
        .ok_or(BootstrapError::InvalidSignerEncoding)
}

fn normalise_hex(input: &str) -> String {
    input.to_ascii_lowercase()
}

/// Parses a scalar identifier from a hex string, normalising case.
pub fn scalar_from_hex(hex: &str) -> Result<Scalar, BootstrapError> {
    parse_scalar_hex(&normalise_hex(hex))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quorum::{aggregate_signatures, happy_path_ceremony, partial_sign};
    use rand_core_06::OsRng;
    use std::time::Duration;

    fn build_signed_list() -> (SignedBootstrapList, TrustedBootstrapQuorum, SystemTime) {
        let mut rng = OsRng;
        let (descriptor, group_pk, shares) = happy_path_ceremony(3, 2, 7, &mut rng);
        let allowed: HashSet<String> = shares
            .iter()
            .map(|share| scalar_to_hex(&share.id))
            .collect();
        let quorum = TrustedBootstrapQuorum::new(descriptor.clone(), group_pk, 2, Some(allowed));

        let mut list = BootstrapList {
            version: SUPPORTED_VERSION,
            published_at: 1_700_000_000,
            expires_at: 1_700_000_000 + 3_600,
            peers: vec![
                BootstrapPeerRecord {
                    peer_id: "12D3KooWS98iFjS4Lf3aQcp5Q3fZwwyT2Qj2jv7NQESGKsTBP1sB".to_string(),
                    addresses: vec![
                        "/ip4/192.0.2.1/udp/9000/quic".to_string(),
                        "/ip4/192.0.2.1/tcp/9001".to_string(),
                    ],
                },
                BootstrapPeerRecord {
                    peer_id: "12D3KooWQ7mA9KyYtXdb7i1LZ1qxGn8pYVHdQp9hw3rrodpAt5YB".to_string(),
                    addresses: vec!["/ip4/198.51.100.2/udp/9000/quic".to_string()],
                },
            ],
        };
        list.canonicalize();

        let message = quorum.signing_message(&list).expect("message");
        let sig1 = partial_sign(&shares[0], &message, SIG_DST);
        let sig2 = partial_sign(&shares[1], &message, SIG_DST);
        let aggregated =
            aggregate_signatures(&[(shares[0].id, sig1), (shares[1].id, sig2)]).expect("aggregate");

        let signed = SignedBootstrapList {
            quorum: descriptor,
            list,
            signature: BootstrapSignature {
                aggregated: signature_to_hex(&aggregated),
                signers: vec![scalar_to_hex(&shares[0].id), scalar_to_hex(&shares[1].id)],
            },
        };

        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000 + 60);
        (signed, quorum, now)
    }

    #[test]
    fn verify_signed_list_success() {
        let (signed, quorum, now) = build_signed_list();
        let peers = verify_signed_list(&signed, &quorum, now).expect("verified");
        assert_eq!(peers.len(), 3);
    }

    #[test]
    fn verify_signed_list_expired() {
        let (mut signed, quorum, _) = build_signed_list();
        signed.list.expires_at = signed.list.published_at - 1;
        let now = UNIX_EPOCH + std::time::Duration::from_secs(signed.list.published_at);
        assert!(matches!(
            verify_signed_list(&signed, &quorum, now),
            Err(BootstrapError::InvalidTimestamps)
        ));

        signed.list.expires_at = signed.list.published_at + 10;
        let after = UNIX_EPOCH + std::time::Duration::from_secs(signed.list.expires_at + 1);
        assert!(matches!(
            verify_signed_list(&signed, &quorum, after),
            Err(BootstrapError::Expired { .. })
        ));
    }

    #[test]
    fn verify_signed_list_bad_signature() {
        let (mut signed, quorum, now) = build_signed_list();
        if let Some(last) = signed.signature.aggregated.pop() {
            signed
                .signature
                .aggregated
                .push(if last == '0' { '1' } else { '0' });
        }
        assert!(matches!(
            verify_signed_list(&signed, &quorum, now),
            Err(BootstrapError::InvalidSignatureEncoding) | Err(BootstrapError::InvalidSignature)
        ));
    }
}
