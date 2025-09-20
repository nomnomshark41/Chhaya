use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use blstrs::{G1Affine, G1Projective};
#[cfg(test)]
use blstrs::{G2Projective, Scalar};
use group::prime::PrimeCurveAffine;
#[cfg(test)]
use group::Group;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core_06::{OsRng, RngCore as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicBool, AtomicU32, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
use zeroize::{Zeroize, Zeroizing};

use libipld::{cbor::DagCborCodec, cid::Cid, codec::Codec, serde::to_ipld};
use libp2p_identity::PeerId;
use multihash::{Code, MultihashDigest};
use tokio::{sync::Mutex, task::JoinHandle, time};
use tracing::warn;

use crate::directory::MerkleProof;
use crate::net::ratelimit::RateLimiter;
use crate::quorum::{bls_verify, QuorumDescriptor, SIG_DST};
use crate::security::audit::{ServerSecretShare, SharedSecret};
use crate::vkd::VkdTrustAnchors;

/// Directory snapshot encoding, verification, and transparency log helpers.
pub mod directory;
/// Networking utilities including rate limiting.
pub mod net;
/// Peer-to-peer transports, exchanges, and bootstrap routines.
pub mod p2p;
/// Local pinning policies for long-term storage backends.
pub mod pin;
/// Threshold BLS quorum coordination helpers.
pub mod quorum;
/// Human-verifiable safety number presentation helpers.
pub mod safety;
/// Secrets handling and audit logging primitives.
pub mod security;
/// Verifiable key directory (VKD) client logic and gossip validation.
pub mod vkd;

use double_ratchet::{DoubleRatchet, Header};
use fips203::ml_kem_1024;
use fips203::traits::{
    Decaps as KemDecaps, Encaps as KemEncaps, KeyGen as KemKeyGen, SerDes as KemSerDes,
};

use sharks::{Share, Sharks};
use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;

const PROTO_VER: &[u8] = b"v1";
const PROTO_SUITE: &[u8] = b"X25519+ML-KEM-1024:AES-256-GCM";
const WIRE_VER: u8 = 1;
const ROLE_I: u8 = 0x49;
const ROLE_R: u8 = 0x52;

fn jitter_pre_auth() {
    let mut rng = OsRng;
    let delay = 3 + (rng.next_u32() % 5) as u64;
    thread::sleep(Duration::from_millis(delay));
}

/// Errors encountered when performing cryptographic operations.
#[derive(Debug)]
pub enum CryptoError {
    Kem,
    Aead,
    Serde,
    Rng,
    InvalidKeyLength,
    ShareRecovery,
    Math,
}

/// Attempts to lock sensitive process state into memory and disable core dumps.
pub fn protect_process() -> std::io::Result<()> {
    #[cfg(unix)]
    unsafe {
        use std::os::raw::{c_int, c_ulong};

        #[repr(C)]
        struct RLimit {
            rlim_cur: c_ulong,
            rlim_max: c_ulong,
        }

        extern "C" {
            fn mlockall(flags: c_int) -> c_int;
            fn setrlimit(resource: c_int, rlim: *const RLimit) -> c_int;
            #[cfg(target_os = "linux")]
            fn prctl(
                option: c_int,
                arg2: c_ulong,
                arg3: c_ulong,
                arg4: c_ulong,
                arg5: c_ulong,
            ) -> c_int;
        }

        const MCL_CURRENT: c_int = 1;
        const MCL_FUTURE: c_int = 2;
        const RLIMIT_CORE: c_int = 4;
        #[cfg(target_os = "linux")]
        const PR_SET_DUMPABLE: c_int = 4;

        if mlockall(MCL_CURRENT | MCL_FUTURE) != 0 {
            return Err(std::io::Error::last_os_error());
        }

        let rlim = RLimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if setrlimit(RLIMIT_CORE, &rlim) != 0 {
            return Err(std::io::Error::last_os_error());
        }

        #[cfg(target_os = "linux")]
        if prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

fn ensure_protected() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = protect_process();
    });
}

/// Trait abstraction over post-quantum key encapsulation mechanisms used by the protocol.
pub trait Kem {
    type PublicKey;
    type SecretKey: Zeroize;
    type Ciphertext;
    fn keypair() -> Result<(Self::PublicKey, Self::SecretKey), CryptoError>;
    fn encapsulate(pk: &Self::PublicKey) -> Result<(Self::Ciphertext, SharedSecret), CryptoError>;
    fn decapsulate(
        ct: &Self::Ciphertext,
        sk: &Self::SecretKey,
    ) -> Result<SharedSecret, CryptoError>;
    fn serialize_pk(pk: &Self::PublicKey) -> Vec<u8>;
    fn deserialize_pk(bytes: &[u8]) -> Result<Self::PublicKey, CryptoError>;
    fn serialize_ct(ct: &Self::Ciphertext) -> Vec<u8>;
    fn deserialize_ct(bytes: &[u8]) -> Result<Self::Ciphertext, CryptoError>;
}

/// ML-KEM-1024 (FIPS 203) binding implementing the [`Kem`] trait.
#[derive(Clone)]
pub struct MlKem1024;
impl Kem for MlKem1024 {
    type PublicKey = ml_kem_1024::EncapsKey;
    type SecretKey = ml_kem_1024::DecapsKey;
    type Ciphertext = ml_kem_1024::CipherText;

    fn keypair() -> Result<(Self::PublicKey, Self::SecretKey), CryptoError> {
        ml_kem_1024::KG::try_keygen().map_err(|_| CryptoError::Kem)
    }
    fn encapsulate(pk: &Self::PublicKey) -> Result<(Self::Ciphertext, SharedSecret), CryptoError> {
        pk.try_encaps()
            .map(|(ssk, ct)| (ct, SharedSecret::from(ssk.into_bytes().to_vec())))
            .map_err(|_| CryptoError::Kem)
    }
    fn decapsulate(
        ct: &Self::Ciphertext,
        sk: &Self::SecretKey,
    ) -> Result<SharedSecret, CryptoError> {
        sk.try_decaps(ct)
            .map(|ssk| SharedSecret::from(ssk.into_bytes().to_vec()))
            .map_err(|_| CryptoError::Kem)
    }
    fn serialize_pk(pk: &Self::PublicKey) -> Vec<u8> {
        pk.clone().into_bytes().to_vec()
    }
    fn deserialize_pk(bytes: &[u8]) -> Result<Self::PublicKey, CryptoError> {
        let arr: [u8; ml_kem_1024::EK_LEN] = bytes.try_into().map_err(|_| CryptoError::Kem)?;
        ml_kem_1024::EncapsKey::try_from_bytes(arr).map_err(|_| CryptoError::Kem)
    }
    fn serialize_ct(ct: &Self::Ciphertext) -> Vec<u8> {
        ct.clone().into_bytes().to_vec()
    }
    fn deserialize_ct(bytes: &[u8]) -> Result<Self::Ciphertext, CryptoError> {
        let arr: [u8; ml_kem_1024::CT_LEN] = bytes.try_into().map_err(|_| CryptoError::Kem)?;
        ml_kem_1024::CipherText::try_from_bytes(arr).map_err(|_| CryptoError::Kem)
    }
}

/// Stateless proof-of-work challenge used to throttle unauthenticated peers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Puzzle {
    pub challenge: [u8; 16],
    pub difficulty: u8,
}

/// Server-issued cookie that lets clients resume handshakes after solving a puzzle.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RetryCookie {
    pub mac: [u8; 32],
    pub ts: u64,
    pub puzzle: Puzzle,
    pub nonce: u64,
}

/// Current version tag for [`RetryCookie`] serialization.
pub const COOKIE_FMT_V1: u8 = 1;

/// Ephemeral server key schedule entry distributed via secret shares.
#[derive(Clone)]
pub struct ServerKey {
    pub key_id: u8,
    pub shares: Vec<ServerSecretShare>,
    pub not_before: u64,
    pub not_after: u64,
}

/// Rolling schedule of server keys constructed from threshold secret shares.
pub struct KeySchedule {
    keys: Vec<ServerKey>,
    overlap_secs: u64,
    threshold: u8,
    share_count: u8,
}

impl KeySchedule {
    /// Creates an empty schedule with the provided threshold and overlap settings.
    pub fn new(threshold: u8, share_count: u8, overlap_secs: u64) -> Self {
        Self {
            keys: Vec::new(),
            overlap_secs,
            threshold,
            share_count,
        }
    }

    /// Inserts a fresh server secret and retires overlapping keys.
    pub fn rotate(&mut self, secret: &[u8; 32], key_id: u8, not_before: u64) {
        let shares = split_server_secret(secret, self.threshold, self.share_count);
        for k in &mut self.keys {
            k.not_after = not_before + self.overlap_secs;
        }
        self.keys.push(ServerKey {
            key_id,
            shares,
            not_before,
            not_after: u64::MAX,
        });
        self.keys.retain(|k| k.not_after > not_before);
    }

    /// Returns all keys valid for the supplied timestamp ordered by recency.
    pub fn active_keys(&self, now_ts: u64) -> Vec<ServerKey> {
        let mut ks: Vec<ServerKey> = self
            .keys
            .iter()
            .filter(|k| now_ts >= k.not_before && now_ts < k.not_after)
            .cloned()
            .collect();
        ks.sort_by_key(|k| Reverse(k.not_before));
        ks
    }

    /// Returns the signature threshold configured for the schedule.
    pub fn threshold(&self) -> u8 {
        self.threshold
    }
}

/// Tracks peer-specific adjustments to proof-of-work difficulty.
#[derive(Default)]
pub struct AdaptivePuzzleDifficulty {
    base: u8,
    ceiling: u8,
    per_id: HashMap<String, u8>,
}

impl AdaptivePuzzleDifficulty {
    /// Builds a difficulty tracker bounded by `base` and `ceiling`.
    pub fn new(base: u8, ceiling: u8) -> Self {
        Self {
            base,
            ceiling,
            per_id: HashMap::new(),
        }
    }

    /// Increases the challenge difficulty for `id` after a failed verification.
    pub fn record_failure(&mut self, id: &str) -> u8 {
        let d = self.per_id.entry(id.to_string()).or_insert(self.base);
        *d = (*d + 1).min(self.ceiling);
        *d
    }

    /// Lowers the challenge difficulty for `id` when they successfully authenticate.
    pub fn record_success(&mut self, id: &str) {
        let d = self.per_id.entry(id.to_string()).or_insert(self.base);
        if *d > self.base {
            *d -= 1;
        }
    }

    /// Returns the current puzzle difficulty configured for `id`.
    pub fn current(&self, id: &str) -> u8 {
        *self.per_id.get(id).unwrap_or(&self.base)
    }
}

/// Splits a server secret into threshold shares for distribution.
pub fn split_server_secret(
    secret: &[u8; 32],
    threshold: u8,
    share_count: u8,
) -> Vec<ServerSecretShare> {
    let sharks = Sharks(threshold);
    let dealer = sharks.dealer(secret);
    dealer
        .take(share_count as usize)
        .map(|s| ServerSecretShare::from(Vec::from(&s)))
        .collect()
}

fn recover_server_secret(
    threshold: u8,
    shares: &[ServerSecretShare],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let sharks = Sharks(threshold);
    let mut parts = Vec::with_capacity(shares.len());
    for s in shares {
        let share = Share::try_from(s.as_slice()).map_err(|_| CryptoError::ShareRecovery)?;
        parts.push(share);
    }
    let secret_vec = sharks
        .recover(parts.as_slice())
        .map_err(|_| CryptoError::ShareRecovery)?;
    let secret = Zeroizing::new(secret_vec);
    let arr: [u8; 32] = secret
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::ShareRecovery)?;
    Ok(Zeroizing::new(arr))
}

fn generate_puzzle(difficulty: u8) -> Puzzle {
    let mut challenge = [0u8; 16];
    OsRng.fill_bytes(&mut challenge);
    Puzzle {
        challenge,
        difficulty,
    }
}

fn leading_zero_bits(b: &[u8]) -> u8 {
    let mut count = 0u8;
    for byte in b {
        if *byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros() as u8;
            break;
        }
    }
    count
}

fn verify_puzzle(p: &Puzzle, nonce: u64) -> bool {
    let mut h = Sha256::new();
    h.update(p.challenge);
    h.update(nonce.to_le_bytes());
    let out = h.finalize();
    leading_zero_bits(&out) >= p.difficulty
}

/// Performs a brute-force search to satisfy the proof-of-work [`Puzzle`].
pub fn solve_puzzle(p: &Puzzle) -> u64 {
    let mut nonce = 0u64;
    loop {
        if verify_puzzle(p, nonce) {
            return nonce;
        }
        nonce = nonce.wrapping_add(1);
    }
}

/// Builds a signed [`RetryCookie`] that binds puzzle, timestamp, and context.
pub fn make_retry_cookie(
    shares: &[ServerSecretShare],
    threshold: u8,
    key_id: u8,
    context: &[u8],
    ts: u64,
    difficulty: u8,
) -> Result<RetryCookie, CryptoError> {
    ensure_protected();
    let secret = recover_server_secret(threshold, shares)?;
    let puzzle = generate_puzzle(difficulty);
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&*secret)
        .map_err(|_| CryptoError::InvalidKeyLength)?;
    mac.update(&[key_id]);
    mac.update(context);
    mac.update(&ts.to_le_bytes());
    mac.update(&puzzle.challenge);
    mac.update(&[puzzle.difficulty]);
    let out = mac.finalize().into_bytes();
    let mut mac32 = [0u8; 32];
    mac32.copy_from_slice(&out);
    Ok(RetryCookie {
        mac: mac32,
        ts,
        puzzle,
        nonce: 0,
    })
}

/// Validates a presented [`RetryCookie`] and checks the associated puzzle solution.
pub fn verify_retry_cookie(
    shares: &[ServerSecretShare],
    threshold: u8,
    key_id: u8,
    context: &[u8],
    now_ts: u64,
    ttl_secs: u64,
    cookie: &RetryCookie,
) -> Result<bool, CryptoError> {
    ensure_protected();
    if now_ts.saturating_sub(cookie.ts) > ttl_secs {
        return Ok(false);
    }
    let secret = recover_server_secret(threshold, shares)?;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&*secret)
        .map_err(|_| CryptoError::InvalidKeyLength)?;
    mac.update(&[key_id]);
    mac.update(context);
    mac.update(&cookie.ts.to_le_bytes());
    mac.update(&cookie.puzzle.challenge);
    mac.update(&[cookie.puzzle.difficulty]);
    let out = mac.finalize().into_bytes();
    let mut expect = [0u8; 32];
    expect.copy_from_slice(&out);
    if cookie.mac.ct_eq(&expect).unwrap_u8() != 1 {
        return Ok(false);
    }
    Ok(verify_puzzle(&cookie.puzzle, cookie.nonce))
}

/// Raw decentralized identifier bytes used across directory records.
pub type Did = Vec<u8>;

/// Published bundle describing a user's cryptographic material and quorum policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryRecord<K: Kem> {
    pub did: Did,
    pub epoch: u64,
    pub x25519_prekey: [u8; 32],
    pub kem_pk: Vec<u8>,
    pub prekey_batch_root: [u8; 32],
    pub quorum_desc: QuorumDescriptor,
    pub sig_idkey: Vec<u8>,
    #[serde(skip)]
    pub bundle_cid: Option<Cid>,
    #[serde(skip)]
    pub quorum_desc_cid: Option<Cid>,
    #[serde(skip)]
    _phantom: std::marker::PhantomData<K>,
}
impl<K: Kem> DirectoryRecord<K> {
    /// Constructs a directory record from the supplied key material and quorum descriptor.
    pub fn new(
        did: Did,
        epoch: u64,
        x25519_prekey: [u8; 32],
        kem_pk: K::PublicKey,
        prekey_batch_root: [u8; 32],
        quorum_desc: QuorumDescriptor,
    ) -> Self {
        Self {
            did,
            epoch,
            x25519_prekey,
            kem_pk: K::serialize_pk(&kem_pk),
            prekey_batch_root,
            quorum_desc,
            sig_idkey: Vec::new(),
            bundle_cid: None,
            quorum_desc_cid: None,
            _phantom: Default::default(),
        }
    }
    /// Returns the embedded KEM public key in its native type.
    pub fn kem_pk(&self) -> Result<K::PublicKey, CryptoError> {
        K::deserialize_pk(&self.kem_pk)
    }
}

/// Server-issued receipt proving a rate-limited spend took place.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpendReceipt {
    pub batch_root: [u8; 32],
    pub nullifier: [u8; 32],
    pub quorum_sig: Vec<u8>,
    pub quorum_epoch: u64,
}

/// Proof material returned by the verifiable key directory service.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VkdProof {
    pub log_id: Vec<u8>,
    pub sth_root_hash: [u8; 32],
    pub sth_tree_size: u64,
    pub sth_time: u64,
    pub sth_sig: Vec<u8>,
    pub witness_sigs: Vec<Vec<u8>>,
    pub inclusion_hash: [u8; 32],
    pub inclusion_proof: MerkleProof,
    pub consistency_proof: Option<Vec<[u8; 32]>>,
    pub vrf_proof: Vec<u8>,
    pub bundle_cid: Cid,
    pub quorum_desc_cid: Cid,
}

/// Locally verified signed tree head for the directory log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedSth {
    pub root_hash: [u8; 32],
    pub tree_size: u64,
    pub sth_time: u64,
    pub log_id: Vec<u8>,
}

/// Validates inclusion, witness, and VRF proofs for a directory record update.
pub fn verify_vkd_proof(
    proof: &VkdProof,
    trust: &VkdTrustAnchors,
    prev_sth: Option<VerifiedSth>,
) -> Option<VerifiedSth> {
    if proof.log_id != trust.log_id() {
        return None;
    }

    if let Some(prev) = prev_sth.as_ref() {
        if prev.log_id != proof.log_id {
            return None;
        }
        if proof.sth_tree_size < prev.tree_size {
            return None;
        }
        if proof.sth_time < prev.sth_time {
            return None;
        }
        if proof.sth_tree_size == prev.tree_size {
            if proof.sth_root_hash != prev.root_hash {
                return None;
            }
        } else if proof.consistency_proof.is_none() {
            return None;
        }
    }

    let mut sth_tuple = Vec::new();
    sth_tuple.extend_from_slice(&proof.sth_root_hash);
    sth_tuple.extend_from_slice(&proof.sth_tree_size.to_le_bytes());
    sth_tuple.extend_from_slice(&proof.sth_time.to_le_bytes());
    sth_tuple.extend_from_slice(&proof.log_id);

    fn g1_from_bytes(bytes: &[u8]) -> Option<G1Projective> {
        let arr: [u8; 48] = bytes.try_into().ok()?;
        let aff = G1Affine::from_compressed(&arr);
        let aff: G1Affine = Option::<G1Affine>::from(aff)?;
        if bool::from(aff.is_identity()) {
            None
        } else {
            Some(G1Projective::from(aff))
        }
    }

    let sth_sig = g1_from_bytes(&proof.sth_sig)?;
    if !bls_verify(trust.log_public_key(), &sth_tuple, &sth_sig, SIG_DST) {
        return None;
    }

    let mut matched = HashSet::new();
    for sig_bytes in &proof.witness_sigs {
        if let Some(sig) = g1_from_bytes(sig_bytes) {
            for (i, pk) in trust.witness_public_keys().iter().enumerate() {
                if !matched.contains(&i) && bls_verify(pk, &sth_tuple, &sig, SIG_DST) {
                    matched.insert(i);
                    break;
                }
            }
        }
    }
    if matched.len() < trust.witness_threshold() {
        return None;
    }

    if !proof
        .inclusion_proof
        .verify(proof.inclusion_hash, proof.sth_root_hash)
    {
        return None;
    }

    if let (Some(prev), Some(cons)) = (prev_sth.as_ref(), proof.consistency_proof.as_ref()) {
        if !verify_consistency(
            prev.tree_size,
            proof.sth_tree_size,
            prev.root_hash,
            proof.sth_root_hash,
            cons,
        ) {
            return None;
        }
    }

    let vrf_sig = g1_from_bytes(&proof.vrf_proof)?;
    if !bls_verify(
        trust.vrf_public_key(),
        &proof.inclusion_hash,
        &vrf_sig,
        SIG_DST,
    ) {
        return None;
    }

    Some(VerifiedSth {
        root_hash: proof.sth_root_hash,
        tree_size: proof.sth_tree_size,
        sth_time: proof.sth_time,
        log_id: proof.log_id.clone(),
    })
}

fn hash_pair_internal(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(a);
    hasher.update(b);
    let o = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&o);
    out
}

fn verify_consistency(
    old_size: u64,
    new_size: u64,
    old_root: [u8; 32],
    new_root: [u8; 32],
    proof: &[[u8; 32]],
) -> bool {
    if old_size == 0 {
        return proof.is_empty();
    }
    if old_size > new_size {
        return false;
    }
    if old_size == new_size {
        return proof.is_empty() && old_root == new_root;
    }
    if proof.is_empty() {
        return false;
    }

    let Ok(mut node) = usize::try_from(old_size.saturating_sub(1)) else {
        return false;
    };
    let Ok(mut last_node) = usize::try_from(new_size.saturating_sub(1)) else {
        return false;
    };

    while node & 1 == 1 {
        node >>= 1;
        last_node >>= 1;
    }

    let mut idx = 0usize;
    let mut old_hash = if node != 0 { proof[idx] } else { old_root };
    let mut new_hash = old_hash;
    if node != 0 {
        idx += 1;
    }

    while node != 0 {
        if node & 1 == 1 {
            if idx >= proof.len() {
                return false;
            }
            let sib = proof[idx];
            idx += 1;
            old_hash = hash_pair_internal(&sib, &old_hash);
            new_hash = hash_pair_internal(&sib, &new_hash);
        } else if node < last_node {
            if idx >= proof.len() {
                return false;
            }
            let sib = proof[idx];
            idx += 1;
            new_hash = hash_pair_internal(&new_hash, &sib);
        }
        node >>= 1;
        last_node >>= 1;
    }

    while last_node != 0 {
        if idx >= proof.len() {
            return false;
        }
        let sib = proof[idx];
        idx += 1;
        new_hash = hash_pair_internal(&new_hash, &sib);
        last_node >>= 1;
    }

    if idx != proof.len() {
        return false;
    }

    old_hash == old_root && new_hash == new_root
}

/// External verifier for rate-limit receipts bound into the handshake.
pub trait SpendVerifier: Send + Sync {
    fn verify_spend_receipt(
        &self,
        did: &Did,
        epoch: u64,
        prekey_batch_root: &[u8; 32],
        nullifier: &[u8; 32],
        quorum_sig: &[u8],
        quorum_epoch: u64,
    ) -> bool;
}

/// Initiator-to-responder handshake payload carried over the transport.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HandshakeInit {
    pub eph_x25519_pub: [u8; 32],
    pub kem_ciphertext: Vec<u8>,
    pub did: Vec<u8>,
    pub epoch: u64,
    pub prekey_batch_root: [u8; 32],
    pub spend: SpendReceipt,
    pub sth_cid: Cid,
    pub bundle_cid: Cid,
    pub vkd_proof: VkdProof,
    pub pad: Vec<u8>,
    pub transcript_bind: [u8; 32],
    pub cookie: Option<RetryCookie>,
}
/// Responder acknowledgement containing AEAD confirmation material.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HandshakeResp {
    pub nonce: [u8; 12],
    pub confirm_tag: Vec<u8>,
}
/// Final confirmation message proving both sides derived the same session keys.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HandshakeConfirm {
    pub nonce: [u8; 12],
    pub tag: Vec<u8>,
}

/// Symmetric material derived from the combined DH + KEM handshake transcripts.
#[derive(Clone, Debug, Zeroize)]
#[zeroize(drop)]
pub struct SessionKeys {
    pub aead_i_key_bytes: [u8; 32],
    pub aead_r_key_bytes: [u8; 32],
    pub handshake_hash: [u8; 32],
}

/// Wrapper marking that the contained [`SessionKeys`] have been authenticated.
#[derive(Clone, Debug)]
pub struct AuthedSession(pub SessionKeys);

/// Tracks handshake transcripts to prevent replay attacks.
pub trait ReplayCache: Send + Sync {
    fn replay_seen_and_mark(&self, session_id: &[u8; 32]) -> bool;
}

fn h256(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = Sha256::new();
    h.update(bytes);
    let o = h.finalize();
    let mut a = [0u8; 32];
    a.copy_from_slice(&o);
    a
}

fn encode_dag_cbor<T>(value: &T) -> Result<Vec<u8>, CryptoError>
where
    T: ?Sized + Serialize,
{
    let ipld = to_ipld(value).map_err(|_| CryptoError::Serde)?;
    DagCborCodec.encode(&ipld).map_err(|_| CryptoError::Serde)
}

fn cid_from_encoded(bytes: &[u8]) -> Cid {
    let multihash = Code::Sha2_256.digest(bytes);
    Cid::new_v1(u64::from(DagCborCodec), multihash)
}

fn directory_record_cid<K: Kem>(record: &DirectoryRecord<K>) -> Result<Cid, CryptoError> {
    let bytes = encode_dag_cbor(record)?;
    Ok(cid_from_encoded(&bytes))
}

fn quorum_descriptor_cid(desc: &QuorumDescriptor) -> Result<Cid, CryptoError> {
    let bytes = encode_dag_cbor(desc)?;
    Ok(cid_from_encoded(&bytes))
}

fn hash_quorum_descriptor(desc: &QuorumDescriptor) -> Result<[u8; 32], CryptoError> {
    let bytes = encode_dag_cbor(desc)?;
    Ok(h256(&bytes))
}

fn sth_cid_from_proof(proof: &VkdProof) -> Result<Cid, CryptoError> {
    let sth_repr = (
        proof.log_id.as_slice(),
        proof.sth_root_hash,
        proof.sth_tree_size,
        proof.sth_time,
        proof.sth_sig.as_slice(),
        &proof.witness_sigs,
    );
    let bytes = encode_dag_cbor(&sth_repr)?;
    Ok(cid_from_encoded(&bytes))
}

fn cid_digest(cid: &Cid) -> [u8; 32] {
    h256(&cid.to_bytes())
}
fn hkdf32(label: &str, ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let mut salt = Vec::new();
    salt.push(WIRE_VER);
    salt.extend_from_slice(PROTO_VER);
    salt.extend_from_slice(PROTO_SUITE);
    salt.extend_from_slice(label.as_bytes());
    let hk = Hkdf::<Sha256>::new(Some(&salt), ikm);
    let mut out = [0u8; 32];
    let res = hk.expand(info, &mut out);
    debug_assert!(res.is_ok(), "HKDF expand cannot fail for 32-byte output");
    out
}
fn hkdf64(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; 64] {
    let mut s = Vec::new();
    s.push(WIRE_VER);
    s.extend_from_slice(PROTO_VER);
    s.extend_from_slice(PROTO_SUITE);
    s.extend_from_slice(salt);
    let hk = Hkdf::<Sha256>::new(Some(&s), ikm);
    let mut out = [0u8; 64];
    let res = hk.expand(info, &mut out);
    debug_assert!(res.is_ok(), "HKDF expand cannot fail for 64-byte output");
    out
}
fn hkdf_n12(ikm: &[u8], info: &[u8]) -> [u8; 12] {
    let mut s = Vec::new();
    s.push(WIRE_VER);
    s.extend_from_slice(PROTO_VER);
    s.extend_from_slice(PROTO_SUITE);
    let hk = Hkdf::<Sha256>::new(Some(&s), ikm);
    let mut out = [0u8; 12];
    let res = hk.expand(info, &mut out);
    debug_assert!(res.is_ok(), "HKDF expand cannot fail for 12-byte output");
    out
}
fn derive_hybrid_secret(ss_dh: &[u8], ss_kem: &[u8]) -> [u8; 32] {
    let mut i = Zeroizing::new(Vec::with_capacity(ss_dh.len() + ss_kem.len()));
    i.extend_from_slice(ss_dh);
    i.extend_from_slice(ss_kem);
    hkdf32("proto-hybrid", &i, &[])
}
fn derive_session(h: &[u8; 32], t: &[u8; 32]) -> SessionKeys {
    let mut seed = Zeroizing::new(Vec::with_capacity(64));
    seed.extend_from_slice(h);
    seed.extend_from_slice(t);
    let hh = h256(&seed);
    let ki_bytes = hkdf32("proto-session-aead-i", &hh, &[]);
    let kr_bytes = hkdf32("proto-session-aead-r", &hh, &[]);
    SessionKeys {
        aead_i_key_bytes: ki_bytes,
        aead_r_key_bytes: kr_bytes,
        handshake_hash: hh,
    }
}
fn derive_final_session(s0: &SessionKeys, extra_dh: &[u8], sr: &[u8; 32]) -> SessionKeys {
    let mut seed = Zeroizing::new(Vec::with_capacity(32 + extra_dh.len() + 32));
    seed.extend_from_slice(&s0.handshake_hash);
    seed.extend_from_slice(extra_dh);
    seed.extend_from_slice(sr);
    let hh = h256(&seed);
    let ki_bytes = hkdf32("proto-session-aead-final-i", &hh, &[]);
    let kr_bytes = hkdf32("proto-session-aead-final-r", &hh, &[]);
    SessionKeys {
        aead_i_key_bytes: ki_bytes,
        aead_r_key_bytes: kr_bytes,
        handshake_hash: hh,
    }
}
fn aead_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    pt: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let aead = Aes256Gcm::new(key.into());
    aead.encrypt(Nonce::from_slice(nonce), Payload { msg: pt, aad })
        .map_err(|_| CryptoError::Aead)
}
fn aead_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ct: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let aead = Aes256Gcm::new(key.into());
    let pt = aead
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| CryptoError::Aead)?;
    Ok(Zeroizing::new(pt))
}
fn dr_root_from_handshake(hh: [u8; 32]) -> [u8; 32] {
    hkdf32("proto-dr-root", &hh, &[])
}
fn session_id_from_bind(bind: &[u8; 32]) -> [u8; 32] {
    h256(bind)
}

fn append_cookie_bytes(buf: &mut Vec<u8>, cookie: &RetryCookie) {
    buf.extend_from_slice(&cookie.mac);
    buf.extend_from_slice(&cookie.ts.to_le_bytes());
    buf.extend_from_slice(&cookie.puzzle.challenge);
    buf.push(cookie.puzzle.difficulty);
    buf.extend_from_slice(&cookie.nonce.to_le_bytes());
}

/// Parses a serialized [`RetryCookie`] emitted by [`make_retry_cookie`].
pub fn decode_retry_cookie(bytes: &[u8]) -> Option<RetryCookie> {
    if bytes.len() != 32 + 8 + 16 + 1 + 8 {
        return None;
    }
    let mut mac = [0u8; 32];
    mac.copy_from_slice(&bytes[..32]);
    let ts = u64::from_le_bytes(bytes[32..40].try_into().ok()?);
    let mut challenge = [0u8; 16];
    challenge.copy_from_slice(&bytes[40..56]);
    let difficulty = bytes[56];
    let nonce = u64::from_le_bytes(bytes[57..65].try_into().ok()?);
    Some(RetryCookie {
        mac,
        ts,
        puzzle: Puzzle {
            challenge,
            difficulty,
        },
        nonce,
    })
}

struct TranscriptBindContext<'a> {
    eph_x25519_pub: &'a [u8; 32],
    x25519_prekey: &'a [u8; 32],
    kem_ciphertext: &'a [u8],
    did: &'a [u8],
    epoch: u64,
    prekey_batch_root: &'a [u8; 32],
    spend: &'a SpendReceipt,
    sth_cid: &'a Cid,
    bundle_cid: &'a Cid,
    quorum_desc_digest: &'a [u8; 32],
    vkd: &'a VkdProof,
    pad: &'a [u8],
    cookie: Option<&'a RetryCookie>,
}

fn compute_transcript_bind_v2(ctx: TranscriptBindContext<'_>) -> [u8; 32] {
    let mut tb = Zeroizing::new(Vec::new());
    tb.extend_from_slice(PROTO_VER);
    tb.extend_from_slice(PROTO_SUITE);
    tb.push(ROLE_I);
    tb.extend_from_slice(ctx.eph_x25519_pub);
    tb.push(ROLE_R);
    tb.extend_from_slice(ctx.x25519_prekey);
    tb.extend_from_slice(ctx.kem_ciphertext);
    tb.extend_from_slice(ctx.did);
    tb.extend_from_slice(&ctx.epoch.to_le_bytes());
    tb.extend_from_slice(ctx.prekey_batch_root);
    tb.extend_from_slice(&ctx.spend.batch_root);
    tb.extend_from_slice(&ctx.spend.nullifier);
    tb.extend_from_slice(&ctx.spend.quorum_sig);
    tb.extend_from_slice(&ctx.spend.quorum_epoch.to_le_bytes());
    let sth_bytes = ctx.sth_cid.to_bytes();
    tb.extend_from_slice(&(sth_bytes.len() as u16).to_le_bytes());
    tb.extend_from_slice(&sth_bytes);
    let bundle_bytes = ctx.bundle_cid.to_bytes();
    tb.extend_from_slice(&(bundle_bytes.len() as u16).to_le_bytes());
    tb.extend_from_slice(&bundle_bytes);
    tb.extend_from_slice(ctx.quorum_desc_digest);
    tb.extend_from_slice(&(ctx.vkd.log_id.len() as u16).to_le_bytes());
    tb.extend_from_slice(&ctx.vkd.log_id);
    tb.extend_from_slice(&ctx.vkd.sth_root_hash);
    tb.extend_from_slice(&ctx.vkd.sth_tree_size.to_le_bytes());
    tb.extend_from_slice(&ctx.vkd.sth_time.to_le_bytes());
    tb.extend_from_slice(&ctx.vkd.inclusion_hash);
    tb.extend_from_slice(&(ctx.vkd.vrf_proof.len() as u16).to_le_bytes());
    tb.extend_from_slice(&ctx.vkd.vrf_proof);
    let bundle_cid_bytes = ctx.vkd.bundle_cid.to_bytes();
    tb.extend_from_slice(&(bundle_cid_bytes.len() as u16).to_le_bytes());
    tb.extend_from_slice(&bundle_cid_bytes);
    let quorum_cid_bytes = ctx.vkd.quorum_desc_cid.to_bytes();
    tb.extend_from_slice(&(quorum_cid_bytes.len() as u16).to_le_bytes());
    tb.extend_from_slice(&quorum_cid_bytes);
    tb.extend_from_slice(ctx.pad);
    if let Some(cookie) = ctx.cookie {
        append_cookie_bytes(&mut tb, cookie);
    }
    h256(&tb)
}

fn proto_aad(role: u8, bind: &[u8; 32]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::new());
    out.push(PROTO_VER.len() as u8);
    out.extend_from_slice(PROTO_VER);
    out.push(PROTO_SUITE.len() as u8);
    out.extend_from_slice(PROTO_SUITE);
    out.push(1);
    out.push(role);
    out.push(bind.len() as u8);
    out.extend_from_slice(bind);
    out
}

/// Associated data prefix for Double Ratchet messages secured by this crate.
pub fn dr_aad() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"DR");
    out.push(PROTO_VER.len() as u8);
    out.extend_from_slice(PROTO_VER);
    out.push(PROTO_SUITE.len() as u8);
    out.extend_from_slice(PROTO_SUITE);
    out
}

fn bucket_pad_len(b: u8) -> usize {
    match b {
        0..=31 => 0,
        32..=63 => 32,
        64..=127 => 64,
        128..=191 => 128,
        _ => 256,
    }
}

fn encode_resp_ok(
    bind: &[u8; 32],
    er_pub: &[u8; 32],
    sr: &[u8; 32],
) -> Result<Vec<u8>, HandshakeError> {
    let mut rng = OsRng;
    let mut pad_len_byte = [0u8; 1];
    rng.try_fill_bytes(&mut pad_len_byte)
        .map_err(|_| HandshakeError::Generic)?;
    let pad_len = bucket_pad_len(pad_len_byte[0]);
    let mut pad = vec![0u8; pad_len];
    if pad_len > 0 {
        rng.try_fill_bytes(&mut pad)
            .map_err(|_| HandshakeError::Generic)?;
    }

    let mut out = Vec::new();
    out.extend_from_slice(b"RESP-OK");
    out.extend_from_slice(bind);
    out.extend_from_slice(er_pub);
    out.extend_from_slice(sr);
    out.extend_from_slice(&(pad_len as u16).to_le_bytes());
    out.extend_from_slice(&pad);
    Ok(out)
}

/// Parses the responder confirmation payload and returns its core fields.
pub fn decode_resp_ok(bytes: &[u8]) -> Option<([u8; 32], [u8; 32], [u8; 32])> {
    let base = 7 + 32 * 3;
    if bytes.len() < base + 2 || &bytes[..7] != b"RESP-OK" {
        return None;
    }
    let pad_len = u16::from_le_bytes(bytes[base..base + 2].try_into().ok()?) as usize;
    if bytes.len() != base + 2 + pad_len {
        return None;
    }
    let mut bind = [0u8; 32];
    bind.copy_from_slice(&bytes[7..39]);
    let mut er = [0u8; 32];
    er.copy_from_slice(&bytes[39..71]);
    let mut sr = [0u8; 32];
    sr.copy_from_slice(&bytes[71..103]);
    Some((bind, er, sr))
}

fn encode_label_hash(label: &[u8], h: &[u8; 32]) -> Result<Vec<u8>, HandshakeError> {
    let mut rng = OsRng;
    let mut pad_len_byte = [0u8; 1];
    rng.try_fill_bytes(&mut pad_len_byte)
        .map_err(|_| HandshakeError::Generic)?;
    let pad_len = bucket_pad_len(pad_len_byte[0]);
    let mut pad = vec![0u8; pad_len];
    if pad_len > 0 {
        rng.try_fill_bytes(&mut pad)
            .map_err(|_| HandshakeError::Generic)?;
    }

    let mut out = Vec::new();
    out.extend_from_slice(label);
    out.extend_from_slice(h);
    out.extend_from_slice(&(pad_len as u16).to_le_bytes());
    out.extend_from_slice(&pad);
    Ok(out)
}

/// Extracts the hashed transcript label from a padded handshake record.
pub fn decode_label_hash(bytes: &[u8], label: &[u8]) -> Option<[u8; 32]> {
    let base = label.len() + 32;
    if bytes.len() < base + 2 || &bytes[..label.len()] != label {
        return None;
    }
    let pad_len = u16::from_le_bytes(bytes[base..base + 2].try_into().ok()?) as usize;
    if bytes.len() != base + 2 + pad_len {
        return None;
    }
    let mut h = [0u8; 32];
    h.copy_from_slice(&bytes[label.len()..label.len() + 32]);
    Some(h)
}

/// Runtime toggles and rate limits for generating cover traffic.
pub struct CoverCfg {
    pub enabled: AtomicBool,
    pub max_msgs_per_min: AtomicU32,
    padding: CoverPadding,
}

impl CoverCfg {
    pub fn new(enabled: bool, max_msgs_per_min: u32, padding: CoverPadding) -> Self {
        Self {
            enabled: AtomicBool::new(enabled),
            max_msgs_per_min: AtomicU32::new(max_msgs_per_min),
            padding,
        }
    }

    pub fn padding(&self) -> &CoverPadding {
        &self.padding
    }
}

impl Clone for CoverCfg {
    fn clone(&self) -> Self {
        Self {
            enabled: AtomicBool::new(self.enabled.load(Ordering::Relaxed)),
            max_msgs_per_min: AtomicU32::new(self.max_msgs_per_min.load(Ordering::Relaxed)),
            padding: self.padding.clone(),
        }
    }
}

impl Default for CoverCfg {
    fn default() -> Self {
        Self::new(true, 120, CoverPadding::default())
    }
}

#[derive(Clone)]
pub struct CoverPadding {
    buckets: Arc<[usize]>,
}

impl CoverPadding {
    pub fn new(mut buckets: Vec<usize>) -> Result<Self, CoverPaddingError> {
        if buckets.is_empty() {
            return Err(CoverPaddingError::Empty);
        }
        buckets.sort_unstable();
        buckets.dedup();
        if buckets.windows(2).any(|window| window[0] == window[1]) {
            return Err(CoverPaddingError::Duplicate);
        }
        if let Some(&last) = buckets.last() {
            if last < ENVELOPE_MIN_TOTAL {
                return Err(CoverPaddingError::BelowMinimum(last));
            }
            if last > ENVELOPE_MAX {
                return Err(CoverPaddingError::ExceedsMaximum(last));
            }
        }
        Ok(Self {
            buckets: Arc::from(buckets.into_boxed_slice()),
        })
    }

    pub fn buckets(&self) -> &[usize] {
        &self.buckets
    }

    pub fn max_bucket(&self) -> usize {
        *self
            .buckets
            .last()
            .expect("CoverPadding requires at least one bucket")
    }

    pub fn bucket_for(&self, len: usize) -> Option<usize> {
        self.buckets.iter().copied().find(|&bucket| bucket >= len)
    }

    pub fn sample_bucket<R: rand_core_06::RngCore>(&self, rng: &mut R) -> usize {
        if self.buckets.len() == 1 {
            return self.buckets[0];
        }
        let idx = (rng.next_u32() as usize) % self.buckets.len();
        self.buckets[idx]
    }
}

impl Default for CoverPadding {
    fn default() -> Self {
        // Buckets span short chat bursts through to the maximum envelope size.
        Self::new(vec![512, 1024, 4096, 8192, 16384, 32768, ENVELOPE_MAX])
            .expect("default padding buckets are valid")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CoverPaddingError {
    #[error("no padding buckets configured")]
    Empty,
    #[error("duplicate padding bucket configured")]
    Duplicate,
    #[error("padding bucket {0} is below minimum envelope size")]
    BelowMinimum(usize),
    #[error("padding bucket {0} exceeds envelope size limit {ENVELOPE_MAX}")]
    ExceedsMaximum(usize),
}

/// Launches a background thread that emits encrypted cover messages.
pub fn spawn_cover_traffic<F>(send: F, stop: Arc<AtomicBool>, cfg: Arc<CoverCfg>)
where
    F: Fn(Vec<u8>) + Send + 'static,
{
    thread::spawn(move || {
        let mut rng = OsRng;
        let mut budget = cfg.max_msgs_per_min.load(Ordering::Relaxed);
        let mut last_refill = Instant::now();
        while !stop.load(Ordering::Relaxed) {
            if last_refill.elapsed() >= Duration::from_secs(60) {
                budget = cfg.max_msgs_per_min.load(Ordering::Relaxed);
                last_refill = Instant::now();
            }
            if cfg.enabled.load(Ordering::Relaxed) && budget > 0 {
                let mut delay_bytes = [0u8; 8];
                rng.fill_bytes(&mut delay_bytes);
                let delay = 100 + (u64::from_le_bytes(delay_bytes) % 900);
                thread::sleep(Duration::from_millis(delay));
                if !cfg.enabled.load(Ordering::Relaxed) {
                    continue;
                }
                let bucket = cfg.padding().sample_bucket(&mut rng);
                let mut msg = vec![0u8; bucket];
                if !msg.is_empty() {
                    rng.fill_bytes(&mut msg);
                }
                send(msg);
                budget -= 1;
            } else {
                thread::sleep(Duration::from_millis(100));
            }
        }
    });
}

/// Renders a user-facing safety code string grouped for manual comparison.
pub fn security_code(data: &[u8]) -> String {
    let mut out = String::new();
    for (i, &b) in data.iter().enumerate() {
        out.push((b'A' + (b >> 4)) as char);
        out.push((b'A' + (b & 0x0F)) as char);
        if i % 4 == 3 && i + 1 != data.len() {
            out.push(' ');
        }
    }
    out
}

/// Sensitive initiator state retained between handshake rounds.
#[derive(Clone)]
pub struct InitiatorState<K: Kem> {
    eph_x_sk: X25519Secret,
    hybrid_secret: [u8; 32],
    transcript_bind: [u8; 32],
    _phantom: std::marker::PhantomData<K>,
}
impl<K: Kem> Drop for InitiatorState<K> {
    fn drop(&mut self) {
        self.eph_x_sk.zeroize();
        self.hybrid_secret.zeroize();
        self.transcript_bind.zeroize();
    }
}

/// Secrets a responder must persist while completing the handshake.
#[derive(Clone)]
pub struct ResponderState<K: Kem> {
    x25519_prekey_sk: X25519Secret,
    kem_sk: K::SecretKey,
    hybrid_secret: [u8; 32],
    transcript_bind: [u8; 32],
    _phantom: std::marker::PhantomData<K>,
}
impl<K: Kem> Drop for ResponderState<K> {
    fn drop(&mut self) {
        self.x25519_prekey_sk.zeroize();
        self.kem_sk.zeroize();
        self.hybrid_secret.zeroize();
        self.transcript_bind.zeroize();
    }
}

/// Generates a fresh directory record and responder state for a new epoch.
pub fn generate_directory_record<K: Kem>(
    did: Did,
    epoch: u64,
    quorum_desc: QuorumDescriptor,
) -> Result<(DirectoryRecord<K>, ResponderState<K>), CryptoError> {
    ensure_protected();
    let x_sk = X25519Secret::random_from_rng(OsRng);
    let x_pk = X25519Public::from(&x_sk);
    let (kem_pk, kem_sk) = K::keypair()?;
    let mut prekey_batch_root = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut prekey_batch_root)
        .map_err(|_| CryptoError::Rng)?;
    Ok((
        DirectoryRecord::<K>::new(
            did,
            epoch,
            x_pk.to_bytes(),
            kem_pk,
            prekey_batch_root,
            quorum_desc,
        ),
        ResponderState::<K> {
            x25519_prekey_sk: x_sk,
            kem_sk,
            hybrid_secret: [0u8; 32],
            transcript_bind: [0u8; 32],
            _phantom: Default::default(),
        },
    ))
}

/// Prepares the initiator handshake message and derived state.
pub fn initiator_handshake_init<K: Kem>(
    dir: &DirectoryRecord<K>,
    spend: SpendReceipt,
    cookie: Option<RetryCookie>,
    vkd_proof: VkdProof,
) -> Result<(HandshakeInit, InitiatorState<K>), HandshakeError> {
    ensure_protected();
    let eph_x_sk = X25519Secret::random_from_rng(OsRng);
    let eph_x_pk = X25519Public::from(&eph_x_sk);
    let rx = X25519Public::from(dir.x25519_prekey);
    let mut ss_dh = eph_x_sk.diffie_hellman(&rx);
    if ss_dh.as_bytes().ct_eq(&[0u8; 32]).into() {
        return Err(HandshakeError::Generic);
    }

    let kem_pk = dir.kem_pk().map_err(|_| HandshakeError::Generic)?;
    let (kem_ct, ss_kem) = K::encapsulate(&kem_pk).map_err(|_| HandshakeError::Generic)?;
    let hybrid = derive_hybrid_secret(ss_dh.as_bytes(), ss_kem.as_ref());
    drop(ss_kem);
    ss_dh.zeroize();
    let kem_ct_bytes = K::serialize_ct(&kem_ct);
    let eph_x_pk_bytes = eph_x_pk.to_bytes();
    let mut l = [0u8; 1];
    OsRng
        .try_fill_bytes(&mut l)
        .map_err(|_| HandshakeError::Generic)?;
    let pad_len = bucket_pad_len(l[0]);
    let mut pad = vec![0u8; pad_len];
    if pad_len > 0 {
        OsRng
            .try_fill_bytes(&mut pad)
            .map_err(|_| HandshakeError::Generic)?;
    }
    let quorum_digest =
        hash_quorum_descriptor(&dir.quorum_desc).map_err(|_| HandshakeError::Generic)?;
    let bundle_cid = directory_record_cid(dir).map_err(|_| HandshakeError::Generic)?;
    let sth_cid = sth_cid_from_proof(&vkd_proof).map_err(|_| HandshakeError::Generic)?;
    let bind = compute_transcript_bind_v2(TranscriptBindContext {
        eph_x25519_pub: &eph_x_pk_bytes,
        x25519_prekey: &dir.x25519_prekey,
        kem_ciphertext: &kem_ct_bytes,
        did: &dir.did,
        epoch: dir.epoch,
        prekey_batch_root: &dir.prekey_batch_root,
        spend: &spend,
        sth_cid: &sth_cid,
        bundle_cid: &bundle_cid,
        quorum_desc_digest: &quorum_digest,
        vkd: &vkd_proof,
        pad: &pad,
        cookie: cookie.as_ref(),
    });

    Ok((
        HandshakeInit {
            eph_x25519_pub: eph_x_pk_bytes,
            kem_ciphertext: kem_ct_bytes,
            did: dir.did.clone(),
            epoch: dir.epoch,
            prekey_batch_root: dir.prekey_batch_root,
            spend,
            sth_cid,
            bundle_cid,
            vkd_proof,
            pad,
            transcript_bind: bind,
            cookie,
        },
        InitiatorState::<K> {
            eph_x_sk,
            hybrid_secret: hybrid,
            transcript_bind: bind,
            _phantom: Default::default(),
        },
    ))
}

/// Errors encountered while driving the handshake state machine.
#[derive(Debug)]
pub enum HandshakeError {
    Retry(RetryCookie),
    Replay,
    TokenUsed,
    Generic,
    DirectoryRollback,
}

/// Runtime inputs required for the responder handshake flow.
pub struct ResponderEnv<'a> {
    pub keys: &'a [ServerKey],
    pub threshold: u8,
    pub now_ts: u64,
    pub ttl_secs: u64,
    pub remote_ip: Option<IpAddr>,
    pub peer_id: Option<&'a PeerId>,
    pub puzzle_id: &'a str,
    pub puzzles: &'a mut AdaptivePuzzleDifficulty,
    pub rate_limiter: &'a mut RateLimiter,
    pub replay: &'a dyn ReplayCache,
    pub spend_verifier: &'a dyn SpendVerifier,
    pub trust_anchors: &'a VkdTrustAnchors,
    pub last_verified_sth: Option<&'a VerifiedSth>,
}

/// Responder-owned context tying together message, directory entry, and secrets.
pub struct ResponderSession<'a, K: Kem> {
    pub message: &'a HandshakeInit,
    pub directory: &'a DirectoryRecord<K>,
    pub state: &'a mut ResponderState<K>,
}
/// Validates the initiator payload and returns the responder's encrypted reply.
pub fn responder_handshake_resp<K: Kem>(
    env: ResponderEnv<'_>,
    session: ResponderSession<'_, K>,
) -> Result<(HandshakeResp, SessionKeys, X25519Secret, X25519Public), HandshakeError> {
    let ResponderEnv {
        keys,
        threshold,
        now_ts,
        ttl_secs,
        remote_ip,
        peer_id,
        puzzle_id,
        puzzles,
        rate_limiter,
        replay,
        spend_verifier,
        trust_anchors,
        last_verified_sth,
    } = env;
    let ResponderSession {
        message: m1,
        directory: dir,
        state: st,
    } = session;
    ensure_protected();
    let ctx = {
        let mut c = Vec::new();
        c.extend_from_slice(&m1.eph_x25519_pub);
        c.extend_from_slice(&m1.kem_ciphertext);
        c.extend_from_slice(&m1.did);
        c.extend_from_slice(&m1.epoch.to_le_bytes());
        c.extend_from_slice(&m1.prekey_batch_root);
        c.extend_from_slice(&m1.spend.batch_root);
        c.extend_from_slice(&m1.spend.nullifier);
        c.extend_from_slice(&m1.spend.quorum_sig);
        c.extend_from_slice(&m1.spend.quorum_epoch.to_le_bytes());
        c.extend_from_slice(&m1.pad);
        c
    };
    let cookie_ok = match &m1.cookie {
        Some(c) => keys.iter().any(|k| {
            verify_retry_cookie(&k.shares, threshold, k.key_id, &ctx, now_ts, ttl_secs, c)
                .unwrap_or(false)
        }),
        None => false,
    };
    if !cookie_ok {
        let diff = puzzles.record_failure(puzzle_id);
        let key = &keys[0];
        let cookie = make_retry_cookie(&key.shares, threshold, key.key_id, &ctx, now_ts, diff)
            .map_err(|_| {
                jitter_pre_auth();
                HandshakeError::Generic
            })?;
        jitter_pre_auth();
        return Err(HandshakeError::Retry(cookie));
    }

    if !rate_limiter.try_acquire(now_ts, remote_ip, peer_id) {
        let diff = puzzles.record_failure(puzzle_id);
        let key = &keys[0];
        let cookie = make_retry_cookie(&key.shares, threshold, key.key_id, &ctx, now_ts, diff)
            .map_err(|_| {
                jitter_pre_auth();
                HandshakeError::Generic
            })?;
        jitter_pre_auth();
        return Err(HandshakeError::Retry(cookie));
    }
    puzzles.record_success(puzzle_id);

    if m1.did != dir.did
        || m1.epoch != dir.epoch
        || m1.prekey_batch_root != dir.prekey_batch_root
        || m1.spend.batch_root != dir.prekey_batch_root
    {
        jitter_pre_auth();
        return Err(HandshakeError::Generic);
    }

    let sth_cid = &m1.sth_cid;
    let bundle_cid_msg = &m1.bundle_cid;

    let vkd = &m1.vkd_proof;
    let quorum_digest = hash_quorum_descriptor(&dir.quorum_desc).map_err(|_| {
        jitter_pre_auth();
        HandshakeError::Generic
    })?;
    let bundle_cid = directory_record_cid(dir).map_err(|_| {
        jitter_pre_auth();
        HandshakeError::Generic
    })?;
    let quorum_cid = quorum_descriptor_cid(&dir.quorum_desc).map_err(|_| {
        jitter_pre_auth();
        HandshakeError::Generic
    })?;
    if bundle_cid_msg != &bundle_cid {
        jitter_pre_auth();
        return Err(HandshakeError::Generic);
    }
    if vkd.bundle_cid != bundle_cid || vkd.quorum_desc_cid != quorum_cid {
        jitter_pre_auth();
        return Err(HandshakeError::Generic);
    }
    let expected_sth_cid = sth_cid_from_proof(vkd).map_err(|_| {
        jitter_pre_auth();
        HandshakeError::Generic
    })?;
    if sth_cid != &expected_sth_cid {
        jitter_pre_auth();
        return Err(HandshakeError::Generic);
    }
    let mut leaf_data = Vec::new();
    leaf_data.extend_from_slice(&dir.did);
    leaf_data.extend_from_slice(&dir.epoch.to_le_bytes());
    leaf_data.extend_from_slice(&dir.x25519_prekey);
    leaf_data.extend_from_slice(&dir.kem_pk);
    leaf_data.extend_from_slice(&dir.prekey_batch_root);
    leaf_data.extend_from_slice(&quorum_digest);
    leaf_data.extend_from_slice(&cid_digest(&bundle_cid));
    leaf_data.extend_from_slice(&cid_digest(&quorum_cid));
    let expected_leaf = h256(&leaf_data);
    if expected_leaf != vkd.inclusion_hash {
        jitter_pre_auth();
        return Err(HandshakeError::Generic);
    }
    let prior_sth = last_verified_sth.cloned();
    if verify_vkd_proof(vkd, trust_anchors, prior_sth).is_none() {
        jitter_pre_auth();
        return Err(HandshakeError::DirectoryRollback);
    }

    let bind = compute_transcript_bind_v2(TranscriptBindContext {
        eph_x25519_pub: &m1.eph_x25519_pub,
        x25519_prekey: &dir.x25519_prekey,
        kem_ciphertext: &m1.kem_ciphertext,
        did: &m1.did,
        epoch: m1.epoch,
        prekey_batch_root: &m1.prekey_batch_root,
        spend: &m1.spend,
        sth_cid: &m1.sth_cid,
        bundle_cid: &m1.bundle_cid,
        quorum_desc_digest: &quorum_digest,
        vkd: &m1.vkd_proof,
        pad: &m1.pad,
        cookie: m1.cookie.as_ref(),
    });
    if bind != m1.transcript_bind {
        jitter_pre_auth();
        return Err(HandshakeError::Generic);
    }

    let sid = session_id_from_bind(&bind);
    if replay.replay_seen_and_mark(&sid) {
        jitter_pre_auth();
        return Err(HandshakeError::Replay);
    }

    if !spend_verifier.verify_spend_receipt(
        &dir.did,
        dir.epoch,
        &dir.prekey_batch_root,
        &m1.spend.nullifier,
        &m1.spend.quorum_sig,
        m1.spend.quorum_epoch,
    ) {
        jitter_pre_auth();
        return Err(HandshakeError::TokenUsed);
    }

    let ie = X25519Public::from(m1.eph_x25519_pub);
    let mut ss_dh = st.x25519_prekey_sk.diffie_hellman(&ie);
    if ss_dh.as_bytes().ct_eq(&[0u8; 32]).into() {
        jitter_pre_auth();
        return Err(HandshakeError::Generic);
    }
    let kem_ct = K::deserialize_ct(&m1.kem_ciphertext).map_err(|_| {
        jitter_pre_auth();
        HandshakeError::Generic
    })?;
    let ss_kem = K::decapsulate(&kem_ct, &st.kem_sk).map_err(|_| {
        jitter_pre_auth();
        HandshakeError::Generic
    })?;
    let hybrid = derive_hybrid_secret(ss_dh.as_bytes(), ss_kem.as_ref());
    drop(ss_kem);
    ss_dh.zeroize();
    st.hybrid_secret = hybrid;
    st.transcript_bind = bind;
    let s0 = derive_session(&hybrid, &bind);

    let er_sk = X25519Secret::random_from_rng(OsRng);
    let er_pub = X25519Public::from(&er_sk);
    let mut s_add = er_sk.diffie_hellman(&ie);
    if s_add.as_bytes().ct_eq(&[0u8; 32]).into() {
        jitter_pre_auth();
        return Err(HandshakeError::Generic);
    }
    let mut rng = OsRng;
    let mut sr = [0u8; 32];
    rng.try_fill_bytes(&mut sr).map_err(|_| {
        jitter_pre_auth();
        HandshakeError::Generic
    })?;

    let n2 = Zeroizing::new(hkdf_n12(&s0.handshake_hash, &[ROLE_R, 2]));
    let aad = proto_aad(ROLE_R, &bind);
    let er_bytes = er_pub.to_bytes();
    let msg = encode_resp_ok(&bind, &er_bytes, &sr).map_err(|_| {
        jitter_pre_auth();
        HandshakeError::Generic
    })?;
    let ct = aead_encrypt(&s0.aead_r_key_bytes, &n2, aad.as_ref(), &msg).map_err(|_| {
        jitter_pre_auth();
        HandshakeError::Generic
    })?;

    let sf = derive_final_session(&s0, s_add.as_bytes(), &sr);
    s_add.zeroize();

    sr.zeroize();
    drop(s_add);

    Ok((
        HandshakeResp {
            nonce: *n2,
            confirm_tag: ct,
        },
        sf,
        er_sk,
        er_pub,
    ))
}

/// Completes the initiator side of the handshake after receiving the responder message.
pub fn initiator_handshake_finalize<K: Kem>(
    m1: &HandshakeInit,
    m2: &HandshakeResp,
    st: &InitiatorState<K>,
) -> Result<(SessionKeys, X25519Public), HandshakeError> {
    ensure_protected();
    let s0 = derive_session(&st.hybrid_secret, &st.transcript_bind);

    let aad = proto_aad(ROLE_R, &m1.transcript_bind);
    let opened = aead_decrypt(
        &s0.aead_r_key_bytes,
        &m2.nonce,
        aad.as_ref(),
        m2.confirm_tag.as_ref(),
    )
    .map_err(|_| HandshakeError::Generic)?;
    let (bind, er_pub_bytes, sr_bytes) = decode_resp_ok(&opened).ok_or(HandshakeError::Generic)?;
    let sr = Zeroizing::new(sr_bytes);
    if bind != m1.transcript_bind {
        return Err(HandshakeError::Generic);
    }

    let er_pub = X25519Public::from(er_pub_bytes);
    let s_add = st.eph_x_sk.diffie_hellman(&er_pub);
    if s_add.as_bytes().ct_eq(&[0u8; 32]).into() {
        return Err(HandshakeError::Generic);
    }
    let sf = derive_final_session(&s0, s_add.as_bytes(), &sr);
    Ok((sf, er_pub))
}

/// Produces the initiator's AEAD-protected confirmation tag.
pub fn initiator_key_confirm(session: &SessionKeys) -> Result<HandshakeConfirm, HandshakeError> {
    ensure_protected();
    let n3 = Zeroizing::new(hkdf_n12(&session.handshake_hash, &[ROLE_I, 3]));

    let aad = proto_aad(ROLE_I, &session.handshake_hash);
    let msg = encode_label_hash(b"INIT-OK", &session.handshake_hash)
        .map_err(|_| HandshakeError::Generic)?;

    let ct = aead_encrypt(&session.aead_i_key_bytes, &n3, aad.as_ref(), &msg)
        .map_err(|_| HandshakeError::Generic)?;
    Ok(HandshakeConfirm {
        nonce: *n3,
        tag: ct,
    })
}
/// Checks the initiator's confirmation tag against the established session.
pub fn responder_verify_initiator(
    session: &SessionKeys,
    m3: &HandshakeConfirm,
) -> Result<(), HandshakeError> {
    ensure_protected();
    let aad = proto_aad(ROLE_I, &session.handshake_hash);
    let opened = aead_decrypt(
        &session.aead_i_key_bytes,
        &m3.nonce,
        aad.as_ref(),
        m3.tag.as_ref(),
    )
    .map_err(|_| HandshakeError::Generic)?;
    let h = decode_label_hash(&opened, b"INIT-OK").ok_or(HandshakeError::Generic)?;
    if h != session.handshake_hash {
        return Err(HandshakeError::Generic);
    }
    Ok(())
}

/// Generates the responder's final confirmation record.
pub fn responder_key_confirm(session: &SessionKeys) -> Result<HandshakeConfirm, HandshakeError> {
    ensure_protected();
    let n4 = Zeroizing::new(hkdf_n12(&session.handshake_hash, &[ROLE_R, 4]));
    let aad = proto_aad(ROLE_R, &session.handshake_hash);
    let msg = encode_label_hash(b"RESP-FIN", &session.handshake_hash)
        .map_err(|_| HandshakeError::Generic)?;
    let ct = aead_encrypt(&session.aead_r_key_bytes, &n4, aad.as_ref(), &msg)
        .map_err(|_| HandshakeError::Generic)?;
    Ok(HandshakeConfirm {
        nonce: *n4,
        tag: ct,
    })
}
/// Validates the responder's confirmation tag.
pub fn initiator_verify_responder(
    session: &SessionKeys,
    m4: &HandshakeConfirm,
) -> Result<(), HandshakeError> {
    ensure_protected();
    let aad = proto_aad(ROLE_R, &session.handshake_hash);
    let opened = aead_decrypt(
        &session.aead_r_key_bytes,
        &m4.nonce,
        aad.as_ref(),
        m4.tag.as_ref(),
    )
    .map_err(|_| HandshakeError::Generic)?;
    let h = decode_label_hash(&opened, b"RESP-FIN").ok_or(HandshakeError::Generic)?;
    if h != session.handshake_hash {
        return Err(HandshakeError::Generic);
    }
    Ok(())
}

mod dr_crypto {
    use aes_gcm::{
        aead::{Aead, Payload},
        Aes256Gcm, KeyInit, Nonce,
    };
    use double_ratchet as dr;
    use hmac::{Hmac, Mac};
    use rand_core_04::{
        CryptoRng as CryptoRng04, Error as Error04, ErrorKind as ErrorKind04, RngCore as RngCore04,
    };
    use rand_core_06::{OsRng, RngCore};
    use sha2::Sha256;
    use x25519_dalek::{PublicKey as XPublic, SharedSecret, StaticSecret};
    use zeroize::{Zeroize, Zeroizing};

    #[derive(Clone, Debug, Hash, PartialEq, Eq)]
    pub struct PublicKey(pub XPublic);
    impl AsRef<[u8]> for PublicKey {
        fn as_ref(&self) -> &[u8] {
            self.0.as_bytes()
        }
    }

    #[derive(Clone)]
    pub struct KeyPair {
        privkey: StaticSecret,
        pub pubkey: PublicKey,
    }

    impl Drop for KeyPair {
        fn drop(&mut self) {
            self.privkey.zeroize();
        }
    }

    impl dr::KeyPair for KeyPair {
        type PublicKey = PublicKey;
        fn new<R>(_: &mut R) -> Self
        where
            R: CryptoRng04 + RngCore04,
        {
            super::ensure_protected();
            let privkey = StaticSecret::random_from_rng(OsRng);
            let pubkey = PublicKey((&privkey).into());
            Self { privkey, pubkey }
        }
        fn public(&self) -> &PublicKey {
            &self.pubkey
        }
    }

    impl KeyPair {
        pub fn from_secret(sk: StaticSecret) -> Self {
            super::ensure_protected();
            let pubkey = PublicKey((&sk).into());
            Self {
                privkey: sk,
                pubkey,
            }
        }
    }

    pub struct CryptoProvider;
    impl dr::CryptoProvider for CryptoProvider {
        type PublicKey = PublicKey;
        type KeyPair = KeyPair;
        type SharedSecret = SharedSecret;
        type RootKey = [u8; 32];
        type ChainKey = [u8; 32];
        type MessageKey = [u8; 32];

        fn diffie_hellman(us: &KeyPair, them: &PublicKey) -> SharedSecret {
            super::ensure_protected();
            us.privkey.diffie_hellman(&them.0)
        }

        fn kdf_rk(rk: &Self::RootKey, s: &SharedSecret) -> (Self::RootKey, Self::ChainKey) {
            super::ensure_protected();
            let mut okm = super::hkdf64(rk, s.as_bytes(), b"dr-rk");
            let mut nrk = [0u8; 32];
            nrk.copy_from_slice(&okm[..32]);
            let mut ck = [0u8; 32];
            ck.copy_from_slice(&okm[32..64]);
            okm.zeroize();
            (nrk, ck)
        }

        fn kdf_ck(ck: &Self::ChainKey) -> (Self::ChainKey, Self::MessageKey) {
            super::ensure_protected();
            let mut mac = match <Hmac<Sha256> as Mac>::new_from_slice(ck) {
                Ok(m) => m,
                Err(_) => panic!("invalid chain key length"),
            };
            mac.update(&[0x01]);
            let mut mk_bytes = mac.finalize().into_bytes();
            let mut mac = match <Hmac<Sha256> as Mac>::new_from_slice(ck) {
                Ok(m) => m,
                Err(_) => panic!("invalid chain key length"),
            };
            mac.update(&[0x02]);
            let mut ck_bytes = mac.finalize().into_bytes();
            let mut mk = [0u8; 32];
            mk.copy_from_slice(&mk_bytes[..32]);
            let mut next = [0u8; 32];
            next.copy_from_slice(&ck_bytes[..32]);
            mk_bytes.zeroize();
            ck_bytes.zeroize();
            (next, mk)
        }

        fn encrypt(key: &Self::MessageKey, pt: &[u8], ad: &[u8]) -> Vec<u8> {
            super::ensure_protected();
            let cipher = Aes256Gcm::new(key.into());
            let nonce_bytes = Zeroizing::new(super::hkdf_n12(key, b"dr-msg-nonce"));
            let nonce = Nonce::from_slice(nonce_bytes.as_ref());
            match cipher.encrypt(nonce, Payload { msg: pt, aad: ad }) {
                Ok(ct) => ct,
                Err(_) => panic!("aead encrypt failure"),
            }
        }

        fn decrypt(
            key: &Self::MessageKey,
            ct: &[u8],
            ad: &[u8],
        ) -> Result<Vec<u8>, dr::DecryptError> {
            super::ensure_protected();
            let cipher = Aes256Gcm::new(key.into());
            let nonce_bytes = Zeroizing::new(super::hkdf_n12(key, b"dr-msg-nonce"));
            let nonce = Nonce::from_slice(nonce_bytes.as_ref());
            cipher
                .decrypt(nonce, Payload { msg: ct, aad: ad })
                .map_err(|_| dr::DecryptError::DecryptFailure)
        }
    }

    pub struct CompatRng(pub OsRng);
    impl RngCore04 for CompatRng {
        fn next_u32(&mut self) -> u32 {
            self.0.next_u32()
        }
        fn next_u64(&mut self) -> u64 {
            self.0.next_u64()
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.0.fill_bytes(dest);
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error04> {
            self.0
                .try_fill_bytes(dest)
                .map_err(|_| Error04::new(ErrorKind04::Unavailable, "os rng"))
        }
    }
    impl CryptoRng04 for CompatRng {}
}

/// Double Ratchet X25519 keypair type used by [`DrPeer`].
pub use dr_crypto::KeyPair as DrKeyPair;

/// Wrapper around the Double Ratchet state machine with the crate's crypto provider.
pub struct DrPeer {
    dr: DoubleRatchet<dr_crypto::CryptoProvider>,
    padding: Arc<CoverPadding>,
}

/// Wire-format Double Ratchet header with fixed-length fields.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeaderWire {
    pub dh: [u8; 32],
    pub n: u32,
    pub pn: u32,
}

const DR_MAX_COUNTER: u32 = 1 << 20;

/// Serialized ciphertext and header emitted by [`DrPeer::send_message`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppMessage {
    pub header: HeaderWire,
    pub ciphertext: Vec<u8>,
}

/// Authenticated application payload to deliver through the Double Ratchet.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedEnvelope {
    pub sender: Vec<u8>,
    pub payload: Vec<u8>,
}

const ENVELOPE_MAX: usize = 64 * 1024;
const ENVELOPE_MIN_TOTAL: usize = 1 + 4 + 4 + 2;
const ENVELOPE_V1: u8 = 1;

fn encode_envelope(env: &SealedEnvelope, padding: &CoverPadding) -> Result<Vec<u8>, CryptoError> {
    let base = 1 + 4 + env.sender.len() + 4 + env.payload.len();
    if base + 2 > ENVELOPE_MAX {
        return Err(CryptoError::Serde);
    }
    let target = padding.bucket_for(base + 2).ok_or(CryptoError::Serde)?;
    let pad_len = target.checked_sub(base + 2).ok_or(CryptoError::Serde)?;
    if pad_len > u16::MAX as usize {
        return Err(CryptoError::Serde);
    }

    let mut out = Vec::with_capacity(target);
    out.push(ENVELOPE_V1);
    out.extend_from_slice(&(env.sender.len() as u32).to_le_bytes());
    out.extend_from_slice(&env.sender);
    out.extend_from_slice(&(env.payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&env.payload);
    out.extend_from_slice(&(pad_len as u16).to_le_bytes());
    if pad_len > 0 {
        let mut pad = vec![0u8; pad_len];
        OsRng.fill_bytes(&mut pad);
        out.extend_from_slice(&pad);
    }
    Ok(out)
}

/// Decodes a sealed envelope emitted by [`encode_envelope`], enforcing size limits.
pub fn decode_envelope(bytes: &[u8]) -> Option<SealedEnvelope> {
    if bytes.len() < 9 || bytes.len() > ENVELOPE_MAX {
        return None;
    }
    if bytes[0] != ENVELOPE_V1 {
        return None;
    }
    let mut idx = 1;
    let sender_len = u32::from_le_bytes(bytes[idx..idx + 4].try_into().ok()?) as usize;
    idx += 4;
    if sender_len > ENVELOPE_MAX || bytes.len() < idx + sender_len + 4 {
        return None;
    }
    let sender = bytes[idx..idx + sender_len].to_vec();
    idx += sender_len;
    let payload_len = u32::from_le_bytes(bytes[idx..idx + 4].try_into().ok()?) as usize;
    idx += 4;
    if payload_len > ENVELOPE_MAX || bytes.len() < idx + payload_len {
        return None;
    }
    if sender_len + payload_len + 11 > ENVELOPE_MAX {
        return None;
    }
    let payload = bytes[idx..idx + payload_len].to_vec();
    idx += payload_len;
    if idx == bytes.len() {
        return Some(SealedEnvelope { sender, payload });
    }
    if bytes.len() < idx + 2 {
        return None;
    }
    let pad_len = u16::from_le_bytes(bytes[idx..idx + 2].try_into().ok()?) as usize;
    idx += 2;
    if bytes.len() != idx + pad_len {
        return None;
    }
    Some(SealedEnvelope { sender, payload })
}

pub type TransportSendResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
pub type TransportSendFuture = Pin<Box<dyn Future<Output = TransportSendResult> + Send>>;
pub type TransportSend = Arc<dyn Fn(AppMessage) -> TransportSendFuture + Send + Sync>;

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("crypto error: {0:?}")]
    Crypto(CryptoError),
    #[error("transport error: {0}")]
    Transport(String),
}

impl From<CryptoError> for SessionError {
    fn from(value: CryptoError) -> Self {
        Self::Crypto(value)
    }
}

pub struct RatchetSession {
    peer: Arc<Mutex<DrPeer>>,
    aad: Arc<Vec<u8>>,
    send: TransportSend,
    cover_cfg: Arc<CoverCfg>,
    cover_stop: Arc<AtomicBool>,
    cover_task: JoinHandle<()>,
}

impl RatchetSession {
    pub fn new_initiator(
        authed: &AuthedSession,
        peer_pub: X25519Public,
        send: TransportSend,
        cover_cfg: Arc<CoverCfg>,
    ) -> Self {
        let padding = Arc::new(cover_cfg.padding().clone());
        let peer = DrPeer::new_initiator_with_padding(authed, peer_pub, padding);
        Self::from_peer(peer, send, cover_cfg, dr_aad())
    }

    pub fn new_responder(
        authed: &AuthedSession,
        kp: dr_crypto::KeyPair,
        send: TransportSend,
        cover_cfg: Arc<CoverCfg>,
    ) -> Self {
        let padding = Arc::new(cover_cfg.padding().clone());
        let peer = DrPeer::new_responder_with_padding(authed, kp, padding);
        Self::from_peer(peer, send, cover_cfg, dr_aad())
    }

    fn from_peer(
        peer: DrPeer,
        send: TransportSend,
        cover_cfg: Arc<CoverCfg>,
        aad: Vec<u8>,
    ) -> Self {
        let peer = Arc::new(Mutex::new(peer));
        let aad = Arc::new(aad);
        let cover_stop = Arc::new(AtomicBool::new(false));
        let cover_task = spawn_async_cover(
            Arc::clone(&peer),
            Arc::clone(&send),
            Arc::clone(&cover_cfg),
            Arc::clone(&aad),
            Arc::clone(&cover_stop),
        );
        Self {
            peer,
            aad,
            send,
            cover_cfg,
            cover_stop,
            cover_task,
        }
    }

    pub fn cover_config(&self) -> Arc<CoverCfg> {
        Arc::clone(&self.cover_cfg)
    }

    pub async fn send_envelope(&self, env: &SealedEnvelope) -> Result<(), SessionError> {
        let mut guard = self.peer.lock().await;
        let msg = guard.send_message(env, self.aad.as_ref())?;
        drop(guard);
        (self.send)(msg)
            .await
            .map_err(|err| SessionError::Transport(err.to_string()))
    }

    pub async fn receive_message(&self, msg: &AppMessage) -> Result<SealedEnvelope, CryptoError> {
        let mut guard = self.peer.lock().await;
        guard.receive_message(msg, self.aad.as_ref())
    }

    pub async fn shutdown(self) -> Result<(), tokio::task::JoinError> {
        self.cover_stop.store(true, Ordering::Relaxed);
        self.cover_task.await
    }
}

fn spawn_async_cover(
    peer: Arc<Mutex<DrPeer>>,
    send: TransportSend,
    cfg: Arc<CoverCfg>,
    aad: Arc<Vec<u8>>,
    stop: Arc<AtomicBool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut rng = OsRng;
        let mut budget = cfg.max_msgs_per_min.load(Ordering::Relaxed);
        let mut last_refill = time::Instant::now();
        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            if last_refill.elapsed() >= Duration::from_secs(60) {
                budget = cfg.max_msgs_per_min.load(Ordering::Relaxed);
                last_refill = time::Instant::now();
            }
            if cfg.enabled.load(Ordering::Relaxed) && budget > 0 {
                let mut delay_bytes = [0u8; 8];
                rng.fill_bytes(&mut delay_bytes);
                let delay = 100 + (u64::from_le_bytes(delay_bytes) % 900);
                time::sleep(Duration::from_millis(delay)).await;
                if stop.load(Ordering::Relaxed) || !cfg.enabled.load(Ordering::Relaxed) {
                    continue;
                }
                let max_sender = cfg.padding().max_bucket().saturating_sub(1 + 4 + 4 + 2);
                let sender_len = if max_sender == 0 {
                    0
                } else {
                    let min_sender = std::cmp::min(16, max_sender);
                    let span = max_sender.saturating_sub(min_sender);
                    let jitter = if span == 0 {
                        0
                    } else {
                        (rng.next_u32() as usize) % (span + 1)
                    };
                    min_sender + jitter
                };
                let mut sender = vec![0u8; sender_len];
                if sender_len > 0 {
                    rng.fill_bytes(&mut sender);
                }
                let header_size = 1 + 4 + sender_len + 4;
                let max_payload = cfg.padding().max_bucket().saturating_sub(header_size + 2);
                let payload_len = if max_payload == 0 {
                    0
                } else {
                    (rng.next_u32() as usize) % (max_payload + 1)
                };
                let mut payload = vec![0u8; payload_len];
                if payload_len > 0 {
                    rng.fill_bytes(&mut payload);
                }
                let env = SealedEnvelope { sender, payload };
                let mut guard = peer.lock().await;
                match guard.send_message(&env, aad.as_ref()) {
                    Ok(msg) => {
                        drop(guard);
                        if let Err(err) = (send)(msg).await {
                            warn!(target: "cover", "cover transport failed: {err}");
                        } else {
                            budget = budget.saturating_sub(1);
                        }
                    }
                    Err(error) => {
                        warn!(target: "cover", "failed to create cover message: {:?}", error);
                    }
                }
            } else {
                time::sleep(Duration::from_millis(100)).await;
            }
        }
    })
}

impl From<&Header<dr_crypto::PublicKey>> for HeaderWire {
    fn from(h: &Header<dr_crypto::PublicKey>) -> Self {
        HeaderWire {
            dh: h.dh.0.to_bytes(),
            n: h.n,
            pn: h.pn,
        }
    }
}

impl From<&HeaderWire> for Header<dr_crypto::PublicKey> {
    fn from(hw: &HeaderWire) -> Self {
        Header {
            dh: dr_crypto::PublicKey(X25519Public::from(hw.dh)),
            n: hw.n,
            pn: hw.pn,
        }
    }
}

impl From<HeaderWire> for Header<dr_crypto::PublicKey> {
    fn from(hw: HeaderWire) -> Self {
        Header {
            dh: dr_crypto::PublicKey(X25519Public::from(hw.dh)),
            n: hw.n,
            pn: hw.pn,
        }
    }
}

impl DrPeer {
    /// Creates a Double Ratchet instance seeded as the initiating party.
    pub fn new_initiator(authed: &AuthedSession, peer_pub: X25519Public) -> Self {
        Self::new_initiator_with_padding(authed, peer_pub, Arc::new(CoverPadding::default()))
    }

    pub fn new_initiator_with_padding(
        authed: &AuthedSession,
        peer_pub: X25519Public,
        padding: Arc<CoverPadding>,
    ) -> Self {
        let root = dr_root_from_handshake((authed.0).handshake_hash);
        let peer = dr_crypto::PublicKey(peer_pub);
        let mut rng = dr_crypto::CompatRng(OsRng);
        let dr = DoubleRatchet::<dr_crypto::CryptoProvider>::new_alice(&root, peer, None, &mut rng);
        Self { dr, padding }
    }
    /// Creates a Double Ratchet instance seeded as the responding party.
    pub fn new_responder(authed: &AuthedSession, kp: dr_crypto::KeyPair) -> Self {
        Self::new_responder_with_padding(authed, kp, Arc::new(CoverPadding::default()))
    }

    pub fn new_responder_with_padding(
        authed: &AuthedSession,
        kp: dr_crypto::KeyPair,
        padding: Arc<CoverPadding>,
    ) -> Self {
        let root = dr_root_from_handshake((authed.0).handshake_hash);
        let dr = DoubleRatchet::<dr_crypto::CryptoProvider>::new_bob(root, kp, None);
        Self { dr, padding }
    }
    /// Encrypts an application payload with the current sending ratchet state.
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        aad: &[u8],
    ) -> (Header<dr_crypto::PublicKey>, Vec<u8>) {
        let mut rng = dr_crypto::CompatRng(OsRng);
        self.dr.ratchet_encrypt(plaintext, aad, &mut rng)
    }
    /// Decrypts a received message and advances the receiving ratchet.
    pub fn decrypt(
        &mut self,
        header: &Header<dr_crypto::PublicKey>,
        ct: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.dr
            .ratchet_decrypt(header, ct, aad)
            .map_err(|_| CryptoError::Aead)
    }

    /// Encrypts and packages an application envelope for transport.
    pub fn send_message(
        &mut self,
        env: &SealedEnvelope,
        aad: &[u8],
    ) -> Result<AppMessage, CryptoError> {
        if env.sender.len() > ENVELOPE_MAX
            || env.payload.len() > ENVELOPE_MAX
            || env.sender.len() + env.payload.len() + 11 > ENVELOPE_MAX
        {
            return Err(CryptoError::Serde);
        }
        let pt = encode_envelope(env, &self.padding)?;
        let (header, ciphertext) = self.encrypt(&pt, aad);
        Ok(AppMessage {
            header: HeaderWire::from(&header),
            ciphertext,
        })
    }

    /// Attempts to decrypt an incoming message into a sealed envelope.
    pub fn receive_message(
        &mut self,
        msg: &AppMessage,
        aad: &[u8],
    ) -> Result<SealedEnvelope, CryptoError> {
        if msg.header.n > DR_MAX_COUNTER || msg.header.pn > DR_MAX_COUNTER {
            return Err(CryptoError::Aead);
        }
        let header: Header<dr_crypto::PublicKey> = Header::from(&msg.header);
        let pt = self.decrypt(&header, &msg.ciphertext, aad)?;
        decode_envelope(&pt).ok_or(CryptoError::Aead)
    }
}

/// Computes a stable fingerprint for a directory bundle to support pinning.
pub fn record_fingerprint<K: Kem>(bundle: &DirectoryRecord<K>) -> [u8; 32] {
    let mut bytes = Vec::new();
    let x25519_len = bundle.x25519_prekey.len() as u16;
    bytes.extend_from_slice(&x25519_len.to_le_bytes());
    bytes.extend_from_slice(&bundle.x25519_prekey);
    let kem_pk_len = bundle.kem_pk.len() as u16;
    bytes.extend_from_slice(&kem_pk_len.to_le_bytes());

    bytes.extend_from_slice(&bundle.kem_pk);
    h256(&bytes)
}

/// Result of verifying a single stored pin against a bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinStatus {
    FirstUse([u8; 32]),
    Match,
    Changed([u8; 32]),
}

/// Outcome of comparing multiple stored pins to a batch of bundles.
#[derive(Debug)]
pub enum MultiPinStatus {
    FirstUse(Vec<[u8; 32]>),
    Match,
    Changed(Vec<[u8; 32]>),
}

/// Checks a bundle against an expected fingerprint and reports state changes.
pub fn verify_record_pin<K: Kem>(
    pinned: Option<[u8; 32]>,
    bundle: &DirectoryRecord<K>,
    warn_callback: Option<&dyn Fn(&str)>,
) -> PinStatus {
    let fp = record_fingerprint(bundle);
    match pinned {
        Some(old) if old == fp => PinStatus::Match,
        Some(old) => {
            let msg = format!(
                "WARNING: bundle fingerprint changed: {} -> {}",
                hex_str(&old),
                hex_str(&fp)
            );
            if let Some(cb) = warn_callback {
                cb(&msg);
            } else {
                eprintln!("{}", msg)
            }
            PinStatus::Changed(fp)
        }
        None => PinStatus::FirstUse(fp),
    }
}

/// Evaluates several bundles against an optional set of stored fingerprints.
pub fn verify_record_pin_multi<K: Kem>(
    pinned: Option<Vec<[u8; 32]>>,
    bundles: &[DirectoryRecord<K>],
) -> MultiPinStatus {
    let fps: Vec<[u8; 32]> = bundles.iter().map(record_fingerprint).collect();
    match pinned {
        Some(list) if fps.iter().any(|fp| list.iter().any(|p| p == fp)) => MultiPinStatus::Match,
        Some(_) => MultiPinStatus::Changed(fps),
        None => MultiPinStatus::FirstUse(fps),
    }
}

/// Writes fingerprint pins to disk in hexadecimal format.
pub fn save_pins<P: AsRef<Path>>(path: P, pins: &[[u8; 32]]) -> io::Result<()> {
    let mut f = File::create(path)?;
    for p in pins {
        writeln!(f, "{}", hex::encode(p))?;
    }
    Ok(())
}

/// Loads fingerprint pins from disk, filtering malformed rows.
pub fn load_pins<P: AsRef<Path>>(path: P) -> io::Result<Option<Vec<[u8; 32]>>> {
    if !path.as_ref().exists() {
        return Ok(None);
    }
    let data = fs::read_to_string(path)?;
    let mut pins = Vec::new();
    for line in data.lines() {
        let bytes = match hex::decode(line) {
            Ok(b) => b,
            Err(_) => continue,
        };
        if bytes.len() != 32 {
            continue;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        pins.push(arr);
    }
    Ok(Some(pins))
}

fn hex_str(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
pub(crate) fn make_receipt(root: [u8; 32]) -> SpendReceipt {
    let mut nullifier = [0u8; 32];
    OsRng.try_fill_bytes(&mut nullifier).unwrap();
    SpendReceipt {
        batch_root: root,
        nullifier,
        quorum_sig: vec![1u8],
        quorum_epoch: 0,
    }
}

#[cfg(test)]
#[derive(Clone)]
pub(crate) struct TestVkdKeys {
    pub trust: VkdTrustAnchors,
    pub log_sk: Scalar,
    pub witness_sks: Vec<Scalar>,
    pub vrf_sk: Scalar,
}

#[cfg(test)]
impl TestVkdKeys {
    pub fn single_witness() -> Self {
        let log_sk = Scalar::from(42u64);
        let witness_sk = Scalar::from(43u64);
        let log_pk = G2Projective::generator() * log_sk;
        let witness_pk = G2Projective::generator() * witness_sk;
        let trust = VkdTrustAnchors::new(b"testlog".to_vec(), log_pk, vec![witness_pk], 1, log_pk)
            .expect("valid VKD trust anchors");
        Self {
            trust,
            log_sk,
            witness_sks: vec![witness_sk],
            vrf_sk: log_sk,
        }
    }
}

#[cfg(test)]
pub(crate) fn sample_quorum_desc(epoch: u64) -> QuorumDescriptor {
    QuorumDescriptor {
        sig_algo: "BLS12381G1_XMD:SHA-256_SSWU_RO".to_string(),
        member_set_hash: [epoch as u8; 32],
        epoch,
    }
}

#[cfg(test)]
pub(crate) fn make_vkd_proof<K: Kem>(record: &DirectoryRecord<K>, keys: &TestVkdKeys) -> VkdProof {
    use crate::directory::TransparencyLog;
    use crate::quorum::bls_sign;
    use group::Curve;
    let mut tlog = TransparencyLog::new();
    let mut leaf_data = Vec::new();
    leaf_data.extend_from_slice(&record.did);
    leaf_data.extend_from_slice(&record.epoch.to_le_bytes());
    leaf_data.extend_from_slice(&record.x25519_prekey);
    leaf_data.extend_from_slice(&record.kem_pk);
    leaf_data.extend_from_slice(&record.prekey_batch_root);
    let quorum_digest = hash_quorum_descriptor(&record.quorum_desc).unwrap();
    let bundle_cid = directory_record_cid(record).unwrap();
    let quorum_cid = quorum_descriptor_cid(&record.quorum_desc).unwrap();
    leaf_data.extend_from_slice(&quorum_digest);
    leaf_data.extend_from_slice(&cid_digest(&bundle_cid));
    leaf_data.extend_from_slice(&cid_digest(&quorum_cid));
    let leaf = h256(&leaf_data);
    tlog.append(leaf).expect("failed to append VKD leaf");
    let proof = tlog.prove(0).unwrap();
    let root = tlog.root();
    let tree_size = 1u64;
    let sth_time = 42u64;
    let mut sth_tuple = Vec::new();
    sth_tuple.extend_from_slice(&root);
    sth_tuple.extend_from_slice(&tree_size.to_le_bytes());
    sth_tuple.extend_from_slice(&sth_time.to_le_bytes());
    sth_tuple.extend_from_slice(keys.trust.log_id());
    let sth_sig = bls_sign(&keys.log_sk, &sth_tuple, SIG_DST)
        .to_affine()
        .to_compressed()
        .to_vec();
    assert_eq!(
        keys.witness_sks.len(),
        keys.trust.witness_public_keys().len(),
        "witness secret keys must match trust anchors",
    );
    let witness_sigs: Vec<Vec<u8>> = keys
        .witness_sks
        .iter()
        .map(|sk| {
            bls_sign(sk, &sth_tuple, SIG_DST)
                .to_affine()
                .to_compressed()
                .to_vec()
        })
        .collect();
    let vrf_sig = bls_sign(&keys.vrf_sk, &leaf, SIG_DST)
        .to_affine()
        .to_compressed()
        .to_vec();
    VkdProof {
        log_id: keys.trust.log_id().to_vec(),
        sth_root_hash: root,
        sth_tree_size: tree_size,
        sth_time,
        sth_sig,
        witness_sigs,
        inclusion_hash: leaf,
        inclusion_proof: proof,
        consistency_proof: None,
        vrf_proof: vrf_sig,
        bundle_cid,
        quorum_desc_cid: quorum_cid,
    }
}

/// Formats the handshake hash into human-friendly verification chunks.
pub fn safety_number(session: &SessionKeys, groups_of_4: usize) -> String {
    let raw = hex(&session.handshake_hash[..10.min(session.handshake_hash.len())]);
    raw.as_bytes()
        .chunks(4)
        .take(groups_of_4)
        .map(|c| {
            debug_assert!(c.iter().all(u8::is_ascii));
            match std::str::from_utf8(c) {
                Ok(s) => s,
                Err(_) => unreachable!("safety_number: hex encoding should produce valid UTF-8"),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::dr_crypto;
    use super::*;
    use crate::net::ratelimit::{RateLimitParams, RateLimiter};
    use crate::vkd::cache::{ProofProcessingResult, ProofQueue};
    use libp2p_identity::{Keypair, PeerId};
    use proptest::prelude::*;
    use std::collections::HashSet;
    use std::fs::{self, File};
    use std::io::{Read, Write};
    use std::path::PathBuf;
    use std::sync::Mutex;
    use tempfile::tempdir;

    #[derive(Default)]
    struct TestReplay(Mutex<HashSet<[u8; 32]>>);
    impl ReplayCache for TestReplay {
        fn replay_seen_and_mark(&self, session_id: &[u8; 32]) -> bool {
            let mut g = self.0.lock().unwrap();
            !g.insert(*session_id)
        }
    }

    #[derive(Default)]
    struct TestSpendVerifier(Mutex<HashSet<[u8; 32]>>);
    impl SpendVerifier for TestSpendVerifier {
        fn verify_spend_receipt(
            &self,
            _did: &Did,
            _epoch: u64,
            _prekey_batch_root: &[u8; 32],
            nullifier: &[u8; 32],
            _quorum_sig: &[u8],
            _quorum_epoch: u64,
        ) -> bool {
            let mut g = self.0.lock().unwrap();
            if g.contains(nullifier) {
                false
            } else {
                g.insert(*nullifier);
                true
            }
        }
    }

    struct FileReplay {
        path: PathBuf,
    }
    impl FileReplay {
        fn new(path: PathBuf) -> Self {
            Self { path }
        }
        fn load(&self) -> HashSet<[u8; 32]> {
            let mut set = HashSet::new();
            if let Ok(mut f) = File::open(&self.path) {
                let mut buf = Vec::new();
                let _ = f.read_to_end(&mut buf);
                for chunk in buf.chunks_exact(32) {
                    let mut id = [0u8; 32];
                    id.copy_from_slice(chunk);
                    set.insert(id);
                }
            }
            set
        }
        fn store(&self, set: &HashSet<[u8; 32]>) {
            let tmp = self.path.with_extension("tmp");
            let mut f = File::create(&tmp).unwrap();
            for id in set {
                f.write_all(id).unwrap();
            }
            f.sync_all().unwrap();
            fs::rename(&tmp, &self.path).unwrap();
            if let Some(parent) = self.path.parent() {
                File::open(parent).unwrap().sync_all().unwrap();
            }
        }
    }
    impl ReplayCache for FileReplay {
        fn replay_seen_and_mark(&self, session_id: &[u8; 32]) -> bool {
            let mut set = self.load();
            if !set.insert(*session_id) {
                true
            } else {
                self.store(&set);
                false
            }
        }
    }

    struct FileNullifier {
        path: PathBuf,
    }
    impl FileNullifier {
        fn new(path: PathBuf) -> Self {
            Self { path }
        }
        fn load(&self) -> HashSet<[u8; 32]> {
            let mut set = HashSet::new();
            if let Ok(mut f) = File::open(&self.path) {
                let mut buf = Vec::new();
                let _ = f.read_to_end(&mut buf);
                for chunk in buf.chunks_exact(32) {
                    let mut id = [0u8; 32];
                    id.copy_from_slice(chunk);
                    set.insert(id);
                }
            }
            set
        }
        fn store(&self, set: &HashSet<[u8; 32]>) {
            let tmp = self.path.with_extension("tmp");
            let mut f = File::create(&tmp).unwrap();
            for id in set {
                f.write_all(id).unwrap();
            }
            f.sync_all().unwrap();
            fs::rename(&tmp, &self.path).unwrap();
            if let Some(parent) = self.path.parent() {
                File::open(parent).unwrap().sync_all().unwrap();
            }
        }
    }
    impl SpendVerifier for FileNullifier {
        fn verify_spend_receipt(
            &self,
            _did: &Did,
            _epoch: u64,
            _prekey_batch_root: &[u8; 32],
            nullifier: &[u8; 32],
            _quorum_sig: &[u8],
            _quorum_epoch: u64,
        ) -> bool {
            let mut set = self.load();
            if !set.insert(*nullifier) {
                false
            } else {
                self.store(&set);
                true
            }
        }
    }

    #[test]
    fn replay_cache_persistence() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("replay.bin");
        let cache = FileReplay::new(path.clone());
        let sid = [1u8; 32];
        assert!(!cache.replay_seen_and_mark(&sid));
        drop(cache);
        let cache2 = FileReplay::new(path);
        assert!(cache2.replay_seen_and_mark(&sid));
    }

    #[test]
    fn nullifier_set_persistence() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("null.bin");
        let verifier = FileNullifier::new(path.clone());
        let nullifier = [2u8; 32];
        assert!(verifier.verify_spend_receipt(&Vec::new(), 0, &[0u8; 32], &nullifier, &[], 0));
        drop(verifier);
        let verifier2 = FileNullifier::new(path);
        assert!(!verifier2.verify_spend_receipt(&Vec::new(), 0, &[0u8; 32], &nullifier, &[], 0));
    }

    fn vkd_proof_chain<K: Kem>(
        record: &DirectoryRecord<K>,
        keys: &TestVkdKeys,
    ) -> (VkdProof, VkdProof) {
        use crate::directory::TransparencyLog;
        use crate::quorum::bls_sign;
        use group::Curve;

        let quorum_digest = hash_quorum_descriptor(&record.quorum_desc).unwrap();
        let bundle_cid = directory_record_cid(record).unwrap();
        let quorum_cid = quorum_descriptor_cid(&record.quorum_desc).unwrap();

        let mut leaf_data = Vec::new();
        leaf_data.extend_from_slice(&record.did);
        leaf_data.extend_from_slice(&record.epoch.to_le_bytes());
        leaf_data.extend_from_slice(&record.x25519_prekey);
        leaf_data.extend_from_slice(&record.kem_pk);
        leaf_data.extend_from_slice(&record.prekey_batch_root);
        leaf_data.extend_from_slice(&quorum_digest);
        leaf_data.extend_from_slice(&cid_digest(&bundle_cid));
        leaf_data.extend_from_slice(&cid_digest(&quorum_cid));
        let leaf = h256(&leaf_data);

        let mut log = TransparencyLog::new();
        log.append(leaf).expect("append initial leaf");
        let proof_initial = log.prove(0).expect("prove initial leaf");
        let root_initial = log.root();
        let tree_size_initial = 1u64;
        let sth_time_initial = 100u64;

        let mut sth_tuple_initial = Vec::new();
        sth_tuple_initial.extend_from_slice(&root_initial);
        sth_tuple_initial.extend_from_slice(&tree_size_initial.to_le_bytes());
        sth_tuple_initial.extend_from_slice(&sth_time_initial.to_le_bytes());
        sth_tuple_initial.extend_from_slice(keys.trust.log_id());
        let sth_sig_initial = bls_sign(&keys.log_sk, &sth_tuple_initial, SIG_DST)
            .to_affine()
            .to_compressed()
            .to_vec();
        let witness_sigs_initial: Vec<Vec<u8>> = keys
            .witness_sks
            .iter()
            .map(|sk| {
                bls_sign(sk, &sth_tuple_initial, SIG_DST)
                    .to_affine()
                    .to_compressed()
                    .to_vec()
            })
            .collect();
        let vrf_sig = bls_sign(&keys.vrf_sk, &leaf, SIG_DST)
            .to_affine()
            .to_compressed()
            .to_vec();

        let initial = VkdProof {
            log_id: keys.trust.log_id().to_vec(),
            sth_root_hash: root_initial,
            sth_tree_size: tree_size_initial,
            sth_time: sth_time_initial,
            sth_sig: sth_sig_initial,
            witness_sigs: witness_sigs_initial,
            inclusion_hash: leaf,
            inclusion_proof: proof_initial,
            consistency_proof: None,
            vrf_proof: vrf_sig.clone(),
            bundle_cid,
            quorum_desc_cid: quorum_cid,
        };

        let extra_leaf = h256(b"directory:next");
        log.append(extra_leaf).expect("append additional leaf");
        let proof_update = log.prove(0).expect("prove updated leaf");
        let consistency_nodes = proof_update.siblings().to_vec();
        let root_update = log.root();
        let tree_size_update = 2u64;
        let sth_time_update = 200u64;

        let mut sth_tuple_update = Vec::new();
        sth_tuple_update.extend_from_slice(&root_update);
        sth_tuple_update.extend_from_slice(&tree_size_update.to_le_bytes());
        sth_tuple_update.extend_from_slice(&sth_time_update.to_le_bytes());
        sth_tuple_update.extend_from_slice(keys.trust.log_id());
        let sth_sig_update = bls_sign(&keys.log_sk, &sth_tuple_update, SIG_DST)
            .to_affine()
            .to_compressed()
            .to_vec();
        let witness_sigs_update: Vec<Vec<u8>> = keys
            .witness_sks
            .iter()
            .map(|sk| {
                bls_sign(sk, &sth_tuple_update, SIG_DST)
                    .to_affine()
                    .to_compressed()
                    .to_vec()
            })
            .collect();

        let update = VkdProof {
            log_id: keys.trust.log_id().to_vec(),
            sth_root_hash: root_update,
            sth_tree_size: tree_size_update,
            sth_time: sth_time_update,
            sth_sig: sth_sig_update,
            witness_sigs: witness_sigs_update,
            inclusion_hash: leaf,
            inclusion_proof: proof_update,
            consistency_proof: Some(consistency_nodes),
            vrf_proof: vrf_sig,
            bundle_cid,
            quorum_desc_cid: quorum_cid,
        };

        (initial, update)
    }

    #[test]
    fn vkd_proof_verification() {
        use crate::directory::TransparencyLog;
        use crate::quorum::bls_sign;
        use group::Curve;
        let keys = TestVkdKeys::single_witness();

        let mut tlog = TransparencyLog::new();
        let leaf = [1u8; 32];
        tlog.append(leaf).expect("failed to append log leaf");
        let root = tlog.root();
        let proof = tlog.prove(0).unwrap();

        let tree_size = 1u64;
        let sth_time = 42u64;
        let mut sth_tuple = Vec::new();
        sth_tuple.extend_from_slice(&root);
        sth_tuple.extend_from_slice(&tree_size.to_le_bytes());
        sth_tuple.extend_from_slice(&sth_time.to_le_bytes());
        sth_tuple.extend_from_slice(keys.trust.log_id());
        let sth_sig = bls_sign(&keys.log_sk, &sth_tuple, SIG_DST)
            .to_affine()
            .to_compressed()
            .to_vec();
        let wit_sig = bls_sign(&keys.witness_sks[0], &sth_tuple, SIG_DST)
            .to_affine()
            .to_compressed()
            .to_vec();

        let vrf_sig = bls_sign(&keys.vrf_sk, &leaf, SIG_DST)
            .to_affine()
            .to_compressed()
            .to_vec();
        let dummy_cid = cid_from_encoded(&[0xAA]);

        let vkd = VkdProof {
            log_id: keys.trust.log_id().to_vec(),
            sth_root_hash: root,
            sth_tree_size: tree_size,
            sth_time,
            sth_sig,
            witness_sigs: vec![wit_sig],
            inclusion_hash: leaf,
            inclusion_proof: proof,
            consistency_proof: None,
            vrf_proof: vrf_sig,
            bundle_cid: dummy_cid,
            quorum_desc_cid: dummy_cid,
        };

        let verified = verify_vkd_proof(&vkd, &keys.trust, None);
        assert!(verified.is_some());
    }

    #[test]
    fn vkd_proof_rejects_wrong_keys() {
        use crate::directory::TransparencyLog;
        use crate::quorum::bls_sign;
        use group::Curve;
        let keys = TestVkdKeys::single_witness();

        let mut tlog = TransparencyLog::new();
        let leaf = [2u8; 32];
        tlog.append(leaf).expect("failed to append log leaf");
        let root = tlog.root();
        let proof = tlog.prove(0).unwrap();

        let tree_size = 1u64;
        let sth_time = 7u64;
        let mut sth_tuple = Vec::new();
        sth_tuple.extend_from_slice(&root);
        sth_tuple.extend_from_slice(&tree_size.to_le_bytes());
        sth_tuple.extend_from_slice(&sth_time.to_le_bytes());
        sth_tuple.extend_from_slice(keys.trust.log_id());
        let sth_sig = bls_sign(&keys.log_sk, &sth_tuple, SIG_DST)
            .to_affine()
            .to_compressed()
            .to_vec();
        let wit_sig = bls_sign(&keys.witness_sks[0], &sth_tuple, SIG_DST)
            .to_affine()
            .to_compressed()
            .to_vec();

        let vrf_sig = bls_sign(&keys.vrf_sk, &leaf, SIG_DST)
            .to_affine()
            .to_compressed()
            .to_vec();
        let dummy_cid = cid_from_encoded(&[0xBB]);

        let vkd = VkdProof {
            log_id: keys.trust.log_id().to_vec(),
            sth_root_hash: root,
            sth_tree_size: tree_size,
            sth_time,
            sth_sig,
            witness_sigs: vec![wit_sig],
            inclusion_hash: leaf,
            inclusion_proof: proof,
            consistency_proof: None,
            vrf_proof: vrf_sig,
            bundle_cid: dummy_cid,
            quorum_desc_cid: dummy_cid,
        };

        let forged_trust = VkdTrustAnchors::new(
            keys.trust.log_id().to_vec(),
            G2Projective::generator() * Scalar::from(99u64),
            keys.trust.witness_public_keys().to_vec(),
            keys.trust.witness_threshold(),
            G2Projective::generator() * Scalar::from(77u64),
        )
        .expect("forged trust");

        assert!(verify_vkd_proof(&vkd, &forged_trust, None).is_none());
    }

    #[test]
    fn vkd_consistency_tampering_rejected() {
        let (record, _) = generate_directory_record::<MlKem1024>(
            b"did:example".to_vec(),
            1,
            sample_quorum_desc(1),
        )
        .unwrap();
        let keys = TestVkdKeys::single_witness();
        let (initial_proof, updated_proof) = vkd_proof_chain(&record, &keys);

        let prior = verify_vkd_proof(&initial_proof, &keys.trust, None)
            .expect("initial proof should verify");
        verify_vkd_proof(&updated_proof, &keys.trust, Some(prior.clone()))
            .expect("updated proof should verify");

        let mut missing_consistency = updated_proof.clone();
        missing_consistency.consistency_proof = None;
        assert!(verify_vkd_proof(&missing_consistency, &keys.trust, Some(prior.clone())).is_none());

        let mut empty_consistency = updated_proof.clone();
        empty_consistency.consistency_proof = Some(Vec::new());
        assert!(verify_vkd_proof(&empty_consistency, &keys.trust, Some(prior.clone())).is_none());

        let mut corrupted_consistency = updated_proof.clone();
        if let Some(ref mut nodes) = corrupted_consistency.consistency_proof {
            if let Some(first) = nodes.first_mut() {
                first[0] ^= 0xAA;
            }
        }
        assert!(verify_vkd_proof(&corrupted_consistency, &keys.trust, Some(prior)).is_none());
    }

    #[test]
    fn envelope_padding_matches_bucket() {
        let padding = CoverPadding::new(vec![128]).unwrap();
        let env = SealedEnvelope {
            sender: vec![1; 10],
            payload: vec![2; 5],
        };
        let encoded = encode_envelope(&env, &padding).unwrap();
        assert_eq!(encoded.len(), 128);
        let decoded = decode_envelope(&encoded).unwrap();
        assert_eq!(decoded.sender, env.sender);
        assert_eq!(decoded.payload, env.payload);
    }

    #[test]
    fn responder_accepts_monotonic_vkd_update() {
        let (record, mut bob_state) = generate_directory_record::<MlKem1024>(
            b"did:example".to_vec(),
            1,
            sample_quorum_desc(1),
        )
        .unwrap();
        let spend = make_receipt(record.prekey_batch_root);
        let replay = TestReplay::default();
        let verifier = TestSpendVerifier::default();
        let server_secret = [7u8; 32];
        let mut schedule = KeySchedule::new(2, 3, u64::MAX);
        schedule.rotate(&server_secret, COOKIE_FMT_V1, 0);
        let mut puzzles = AdaptivePuzzleDifficulty::new(4, 8);
        let mut rate_limiter = RateLimiter::unlimited();

        let vkd_keys = TestVkdKeys::single_witness();
        let (initial_proof, updated_proof) = vkd_proof_chain(&record, &vkd_keys);
        let temp = tempdir().expect("tempdir");
        let queue = ProofQueue::new(temp.path()).expect("queue");
        queue.enqueue(&initial_proof).expect("enqueue initial");
        let results = queue
            .process_pending(&vkd_keys.trust)
            .expect("process initial");
        match results.as_slice() {
            [ProofProcessingResult::Accepted { .. }] => {}
            other => panic!("unexpected processing result {other:?}"),
        }
        let cached_sth = queue
            .last_verified_for(vkd_keys.trust.log_id())
            .expect("load cache")
            .expect("cached sth present");

        let (mut m1, mut alice_state) =
            initiator_handshake_init::<MlKem1024>(&record, spend.clone(), None, updated_proof)
                .expect("initiator init");
        let keys = schedule.active_keys(1_000_000);
        let retry = match responder_handshake_resp::<MlKem1024>(
            ResponderEnv {
                keys: &keys,
                threshold: schedule.threshold(),
                now_ts: 1_000_000,
                ttl_secs: 300,
                remote_ip: None,
                peer_id: None,
                puzzle_id: "client1",
                puzzles: &mut puzzles,
                rate_limiter: &mut rate_limiter,
                replay: &replay,
                spend_verifier: &verifier,
                trust_anchors: &vkd_keys.trust,
                last_verified_sth: Some(&cached_sth),
            },
            ResponderSession {
                message: &m1,
                directory: &record,
                state: &mut bob_state,
            },
        ) {
            Err(HandshakeError::Retry(cookie)) => cookie,
            Err(other) => panic!("unexpected handshake error: {other:?}"),
            Ok(_) => panic!("expected retry without cookie"),
        };

        let mut solved = retry.clone();
        solved.nonce = solve_puzzle(&solved.puzzle);
        m1.cookie = Some(solved);
        let quorum_digest = hash_quorum_descriptor(&record.quorum_desc).unwrap();
        m1.transcript_bind = compute_transcript_bind_v2(TranscriptBindContext {
            eph_x25519_pub: &m1.eph_x25519_pub,
            x25519_prekey: &record.x25519_prekey,
            kem_ciphertext: &m1.kem_ciphertext,
            did: &m1.did,
            epoch: m1.epoch,
            prekey_batch_root: &m1.prekey_batch_root,
            spend: &m1.spend,
            sth_cid: &m1.sth_cid,
            bundle_cid: &m1.bundle_cid,
            quorum_desc_digest: &quorum_digest,
            vkd: &m1.vkd_proof,
            pad: &m1.pad,
            cookie: m1.cookie.as_ref(),
        });
        alice_state.transcript_bind = m1.transcript_bind;

        let keys = schedule.active_keys(1_000_010);
        let result = responder_handshake_resp::<MlKem1024>(
            ResponderEnv {
                keys: &keys,
                threshold: schedule.threshold(),
                now_ts: 1_000_010,
                ttl_secs: 300,
                remote_ip: None,
                peer_id: None,
                puzzle_id: "client1",
                puzzles: &mut puzzles,
                rate_limiter: &mut rate_limiter,
                replay: &replay,
                spend_verifier: &verifier,
                trust_anchors: &vkd_keys.trust,
                last_verified_sth: Some(&cached_sth),
            },
            ResponderSession {
                message: &m1,
                directory: &record,
                state: &mut bob_state,
            },
        );
        assert!(result.is_ok(), "monotonic VKD update should be accepted");
    }

    #[test]
    fn responder_rejects_stale_vkd_proof() {
        let (record, mut bob_state) = generate_directory_record::<MlKem1024>(
            b"did:example".to_vec(),
            1,
            sample_quorum_desc(1),
        )
        .unwrap();
        let spend = make_receipt(record.prekey_batch_root);
        let replay = TestReplay::default();
        let verifier = TestSpendVerifier::default();
        let server_secret = [11u8; 32];
        let mut schedule = KeySchedule::new(2, 3, u64::MAX);
        schedule.rotate(&server_secret, COOKIE_FMT_V1, 0);
        let mut puzzles = AdaptivePuzzleDifficulty::new(4, 8);
        let mut rate_limiter = RateLimiter::unlimited();

        let vkd_keys = TestVkdKeys::single_witness();
        let (initial_proof, updated_proof) = vkd_proof_chain(&record, &vkd_keys);
        let temp = tempdir().expect("tempdir");
        let queue = ProofQueue::new(temp.path()).expect("queue");
        queue.enqueue(&initial_proof).expect("enqueue initial");
        queue
            .process_pending(&vkd_keys.trust)
            .expect("process initial");
        queue.enqueue(&updated_proof).expect("enqueue updated");
        queue
            .process_pending(&vkd_keys.trust)
            .expect("process updated");
        let cached_latest = queue
            .last_verified_for(vkd_keys.trust.log_id())
            .expect("load cache")
            .expect("latest sth present");

        let (mut m1, _) =
            initiator_handshake_init::<MlKem1024>(&record, spend, None, initial_proof)
                .expect("initiator init");
        let keys = schedule.active_keys(1_000_000);
        let retry = match responder_handshake_resp::<MlKem1024>(
            ResponderEnv {
                keys: &keys,
                threshold: schedule.threshold(),
                now_ts: 1_000_000,
                ttl_secs: 300,
                remote_ip: None,
                peer_id: None,
                puzzle_id: "client1",
                puzzles: &mut puzzles,
                rate_limiter: &mut rate_limiter,
                replay: &replay,
                spend_verifier: &verifier,
                trust_anchors: &vkd_keys.trust,
                last_verified_sth: Some(&cached_latest),
            },
            ResponderSession {
                message: &m1,
                directory: &record,
                state: &mut bob_state,
            },
        ) {
            Err(HandshakeError::Retry(cookie)) => cookie,
            Err(other) => panic!("unexpected handshake error: {other:?}"),
            Ok(_) => panic!("expected retry without cookie"),
        };

        let mut solved = retry.clone();
        solved.nonce = solve_puzzle(&solved.puzzle);
        m1.cookie = Some(solved);
        let quorum_digest = hash_quorum_descriptor(&record.quorum_desc).unwrap();
        m1.transcript_bind = compute_transcript_bind_v2(TranscriptBindContext {
            eph_x25519_pub: &m1.eph_x25519_pub,
            x25519_prekey: &record.x25519_prekey,
            kem_ciphertext: &m1.kem_ciphertext,
            did: &m1.did,
            epoch: m1.epoch,
            prekey_batch_root: &m1.prekey_batch_root,
            spend: &m1.spend,
            sth_cid: &m1.sth_cid,
            bundle_cid: &m1.bundle_cid,
            quorum_desc_digest: &quorum_digest,
            vkd: &m1.vkd_proof,
            pad: &m1.pad,
            cookie: m1.cookie.as_ref(),
        });

        let keys = schedule.active_keys(1_000_010);
        match responder_handshake_resp::<MlKem1024>(
            ResponderEnv {
                keys: &keys,
                threshold: schedule.threshold(),
                now_ts: 1_000_010,
                ttl_secs: 300,
                remote_ip: None,
                peer_id: None,
                puzzle_id: "client1",
                puzzles: &mut puzzles,
                rate_limiter: &mut rate_limiter,
                replay: &replay,
                spend_verifier: &verifier,
                trust_anchors: &vkd_keys.trust,
                last_verified_sth: Some(&cached_latest),
            },
            ResponderSession {
                message: &m1,
                directory: &record,
                state: &mut bob_state,
            },
        ) {
            Err(HandshakeError::DirectoryRollback) => {}
            Err(other) => panic!("unexpected handshake error: {other:?}"),
            Ok(_) => panic!("stale proof should have been rejected"),
        }
    }

    #[test]
    fn responder_rejects_consistency_tampering() {
        let (record, bob_state) = generate_directory_record::<MlKem1024>(
            b"did:example".to_vec(),
            1,
            sample_quorum_desc(1),
        )
        .unwrap();
        let vkd_keys = TestVkdKeys::single_witness();
        let (initial_proof, updated_proof) = vkd_proof_chain(&record, &vkd_keys);

        let temp = tempdir().expect("tempdir");
        let queue = ProofQueue::new(temp.path()).expect("queue");
        queue.enqueue(&initial_proof).expect("enqueue initial");
        let results = queue
            .process_pending(&vkd_keys.trust)
            .expect("process initial");
        match results.as_slice() {
            [ProofProcessingResult::Accepted { .. }] => {}
            other => panic!("unexpected processing result {other:?}"),
        }
        let cached_sth = queue
            .last_verified_for(vkd_keys.trust.log_id())
            .expect("load cache")
            .expect("cached sth present");

        let server_secret = [13u8; 32];

        let attempt = |proof: VkdProof| -> Result<(), HandshakeError> {
            let spend = make_receipt(record.prekey_batch_root);
            let replay = TestReplay::default();
            let verifier = TestSpendVerifier::default();
            let mut schedule = KeySchedule::new(2, 3, u64::MAX);
            schedule.rotate(&server_secret, COOKIE_FMT_V1, 0);
            let mut puzzles = AdaptivePuzzleDifficulty::new(4, 8);
            let mut rate_limiter = RateLimiter::unlimited();
            let mut bob_state_local = bob_state.clone();

            let (mut m1, mut alice_state) =
                initiator_handshake_init::<MlKem1024>(&record, spend, None, proof)?;
            let keys = schedule.active_keys(1_000_000);
            let retry = match responder_handshake_resp::<MlKem1024>(
                ResponderEnv {
                    keys: &keys,
                    threshold: schedule.threshold(),
                    now_ts: 1_000_000,
                    ttl_secs: 300,
                    remote_ip: None,
                    peer_id: None,
                    puzzle_id: "client1",
                    puzzles: &mut puzzles,
                    rate_limiter: &mut rate_limiter,
                    replay: &replay,
                    spend_verifier: &verifier,
                    trust_anchors: &vkd_keys.trust,
                    last_verified_sth: Some(&cached_sth),
                },
                ResponderSession {
                    message: &m1,
                    directory: &record,
                    state: &mut bob_state_local,
                },
            ) {
                Err(HandshakeError::Retry(cookie)) => cookie,
                Err(other) => return Err(other),
                Ok(_) => return Err(HandshakeError::Generic),
            };

            let mut solved = retry.clone();
            solved.nonce = solve_puzzle(&solved.puzzle);
            m1.cookie = Some(solved);
            let quorum_digest = hash_quorum_descriptor(&record.quorum_desc).unwrap();
            m1.transcript_bind = compute_transcript_bind_v2(TranscriptBindContext {
                eph_x25519_pub: &m1.eph_x25519_pub,
                x25519_prekey: &record.x25519_prekey,
                kem_ciphertext: &m1.kem_ciphertext,
                did: &m1.did,
                epoch: m1.epoch,
                prekey_batch_root: &m1.prekey_batch_root,
                spend: &m1.spend,
                sth_cid: &m1.sth_cid,
                bundle_cid: &m1.bundle_cid,
                quorum_desc_digest: &quorum_digest,
                vkd: &m1.vkd_proof,
                pad: &m1.pad,
                cookie: m1.cookie.as_ref(),
            });
            alice_state.transcript_bind = m1.transcript_bind;

            let keys = schedule.active_keys(1_000_010);
            responder_handshake_resp::<MlKem1024>(
                ResponderEnv {
                    keys: &keys,
                    threshold: schedule.threshold(),
                    now_ts: 1_000_010,
                    ttl_secs: 300,
                    remote_ip: None,
                    peer_id: None,
                    puzzle_id: "client1",
                    puzzles: &mut puzzles,
                    rate_limiter: &mut rate_limiter,
                    replay: &replay,
                    spend_verifier: &verifier,
                    trust_anchors: &vkd_keys.trust,
                    last_verified_sth: Some(&cached_sth),
                },
                ResponderSession {
                    message: &m1,
                    directory: &record,
                    state: &mut bob_state_local,
                },
            )
            .map(|_| ())
        };

        attempt(updated_proof.clone()).expect("valid proof should succeed");

        let mut missing = updated_proof.clone();
        missing.consistency_proof = None;
        assert!(matches!(
            attempt(missing),
            Err(HandshakeError::DirectoryRollback)
        ));

        let mut empty = updated_proof.clone();
        empty.consistency_proof = Some(Vec::new());
        assert!(matches!(
            attempt(empty),
            Err(HandshakeError::DirectoryRollback)
        ));

        let mut corrupted = updated_proof;
        if let Some(ref mut nodes) = corrupted.consistency_proof {
            if let Some(first) = nodes.first_mut() {
                first[0] ^= 0x44;
            }
        }
        assert!(matches!(
            attempt(corrupted),
            Err(HandshakeError::DirectoryRollback)
        ));
    }

    #[test]
    fn full_flow_with_spend() -> Result<(), HandshakeError> {
        let (record, mut bob_state) = generate_directory_record::<MlKem1024>(
            b"did:example".to_vec(),
            1,
            sample_quorum_desc(1),
        )
        .unwrap();
        let spend = make_receipt(record.prekey_batch_root);
        let replay = TestReplay::default();
        let verifier = TestSpendVerifier::default();
        let server_secret = [9u8; 32];
        let mut schedule = KeySchedule::new(2, 3, u64::MAX);
        schedule.rotate(&server_secret, COOKIE_FMT_V1, 0);
        let mut puzzles = AdaptivePuzzleDifficulty::new(4, 8);
        let mut rate_limiter = RateLimiter::unlimited();

        let vkd_keys = TestVkdKeys::single_witness();
        let vkd = make_vkd_proof(&record, &vkd_keys);
        let (m1, mut alice_state) =
            initiator_handshake_init::<MlKem1024>(&record, spend.clone(), None, vkd).unwrap();
        let keys = schedule.active_keys(1_000_000);
        let retry = match responder_handshake_resp::<MlKem1024>(
            ResponderEnv {
                keys: &keys,
                threshold: schedule.threshold(),
                now_ts: 1_000_000,
                ttl_secs: 300,
                remote_ip: None,
                peer_id: None,
                puzzle_id: "client1",
                puzzles: &mut puzzles,
                rate_limiter: &mut rate_limiter,
                replay: &replay,
                spend_verifier: &verifier,
                trust_anchors: &vkd_keys.trust,
                last_verified_sth: None,
            },
            ResponderSession {
                message: &m1,
                directory: &record,
                state: &mut bob_state,
            },
        ) {
            Err(HandshakeError::Retry(c)) => c,
            _ => panic!("expected retry"),
        };

        let mut solved = retry.clone();
        solved.nonce = solve_puzzle(&solved.puzzle);
        let mut m1_retry = m1.clone();
        m1_retry.cookie = Some(solved);
        let quorum_digest = hash_quorum_descriptor(&record.quorum_desc).unwrap();
        m1_retry.transcript_bind = compute_transcript_bind_v2(TranscriptBindContext {
            eph_x25519_pub: &m1_retry.eph_x25519_pub,
            x25519_prekey: &record.x25519_prekey,
            kem_ciphertext: &m1_retry.kem_ciphertext,
            did: &m1_retry.did,
            epoch: m1_retry.epoch,
            prekey_batch_root: &m1_retry.prekey_batch_root,
            spend: &m1_retry.spend,
            sth_cid: &m1_retry.sth_cid,
            bundle_cid: &m1_retry.bundle_cid,
            quorum_desc_digest: &quorum_digest,
            vkd: &m1_retry.vkd_proof,
            pad: &m1_retry.pad,
            cookie: m1_retry.cookie.as_ref(),
        });
        alice_state.transcript_bind = m1_retry.transcript_bind;
        let keys = schedule.active_keys(1_000_010);
        let (m2, bob_sf, bob_dr_sk, bob_dr_pub) = responder_handshake_resp::<MlKem1024>(
            ResponderEnv {
                keys: &keys,
                threshold: schedule.threshold(),
                now_ts: 1_000_010,
                ttl_secs: 300,
                remote_ip: None,
                peer_id: None,
                puzzle_id: "client1",
                puzzles: &mut puzzles,
                rate_limiter: &mut rate_limiter,
                replay: &replay,
                spend_verifier: &verifier,
                trust_anchors: &vkd_keys.trust,
                last_verified_sth: None,
            },
            ResponderSession {
                message: &m1_retry,
                directory: &record,
                state: &mut bob_state,
            },
        )
        .unwrap();

        let (alice_sf, bob_dr_pub2) =
            initiator_handshake_finalize::<MlKem1024>(&m1_retry, &m2, &alice_state).unwrap();
        assert_eq!(bob_dr_pub.as_bytes(), bob_dr_pub2.as_bytes());
        let m3 = initiator_key_confirm(&alice_sf)?;
        responder_verify_initiator(&bob_sf, &m3)?;
        let m4 = responder_key_confirm(&bob_sf)?;
        initiator_verify_responder(&alice_sf, &m4)?;

        let authed_alice = AuthedSession(alice_sf.clone());
        let authed_bob = AuthedSession(bob_sf.clone());
        let mut a = DrPeer::new_initiator(&authed_alice, bob_dr_pub);
        let bob_kp = dr_crypto::KeyPair::from_secret(bob_dr_sk);
        let mut b = DrPeer::new_responder(&authed_bob, bob_kp);
        let aad = dr_aad();
        let env = SealedEnvelope {
            sender: b"alice".to_vec(),
            payload: b"hi bob".to_vec(),
        };
        let msg = a.send_message(&env, &aad).unwrap();
        let pt = b.receive_message(&msg, &aad).unwrap();
        assert_eq!(&pt.payload, b"hi bob");

        let cover_cfg = Arc::new(CoverCfg::new(true, 0, CoverPadding::default()));
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let transport: TransportSend = {
            let tx = tx.clone();
            Arc::new(move |msg: AppMessage| {
                let tx = tx.clone();
                Box::pin(async move {
                    let _ = tx.send(msg).await;
                    Ok(())
                })
            })
        };
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let session = RatchetSession::new_initiator(
                &authed_alice,
                bob_dr_pub,
                Arc::clone(&transport),
                Arc::clone(&cover_cfg),
            );
            let env = SealedEnvelope {
                sender: b"alice".to_vec(),
                payload: b"hi session".to_vec(),
            };
            session.send_envelope(&env).await.unwrap();
            let delivered = rx.recv().await.expect("session emitted message");
            assert!(!delivered.ciphertext.is_empty());
            session.shutdown().await.unwrap();
        });
        Ok(())
    }

    #[test]
    fn replay_and_spend_reject() {
        let (record, mut bob_state) = generate_directory_record::<MlKem1024>(
            b"did:example".to_vec(),
            1,
            sample_quorum_desc(1),
        )
        .unwrap();
        let spend = make_receipt(record.prekey_batch_root);
        let replay = TestReplay::default();
        let verifier = TestSpendVerifier::default();
        let server_secret = [9u8; 32];
        let mut schedule = KeySchedule::new(2, 3, u64::MAX);
        schedule.rotate(&server_secret, COOKIE_FMT_V1, 0);
        let mut puzzles = AdaptivePuzzleDifficulty::new(4, 8);
        let mut rate_limiter = RateLimiter::unlimited();

        let vkd_keys = TestVkdKeys::single_witness();
        let vkd = make_vkd_proof(&record, &vkd_keys);
        let (m1, _) =
            initiator_handshake_init::<MlKem1024>(&record, spend.clone(), None, vkd).unwrap();
        let keys = schedule.active_keys(1_000_000);
        let retry = match responder_handshake_resp::<MlKem1024>(
            ResponderEnv {
                keys: &keys,
                threshold: schedule.threshold(),
                now_ts: 1_000_000,
                ttl_secs: 300,
                remote_ip: None,
                peer_id: None,
                puzzle_id: "client1",
                puzzles: &mut puzzles,
                rate_limiter: &mut rate_limiter,
                replay: &replay,
                spend_verifier: &verifier,
                trust_anchors: &vkd_keys.trust,
                last_verified_sth: None,
            },
            ResponderSession {
                message: &m1,
                directory: &record,
                state: &mut bob_state,
            },
        ) {
            Err(HandshakeError::Retry(c)) => c,
            _ => panic!("expected retry"),
        };
        let mut solved = retry.clone();
        solved.nonce = solve_puzzle(&solved.puzzle);
        let mut m1_retry = m1.clone();
        m1_retry.cookie = Some(solved);
        let quorum_digest = hash_quorum_descriptor(&record.quorum_desc).unwrap();
        m1_retry.transcript_bind = compute_transcript_bind_v2(TranscriptBindContext {
            eph_x25519_pub: &m1_retry.eph_x25519_pub,
            x25519_prekey: &record.x25519_prekey,
            kem_ciphertext: &m1_retry.kem_ciphertext,
            did: &m1_retry.did,
            epoch: m1_retry.epoch,
            prekey_batch_root: &m1_retry.prekey_batch_root,
            spend: &m1_retry.spend,
            sth_cid: &m1_retry.sth_cid,
            bundle_cid: &m1_retry.bundle_cid,
            quorum_desc_digest: &quorum_digest,
            vkd: &m1_retry.vkd_proof,
            pad: &m1_retry.pad,
            cookie: m1_retry.cookie.as_ref(),
        });
        let keys = schedule.active_keys(1_000_010);
        let _ = responder_handshake_resp::<MlKem1024>(
            ResponderEnv {
                keys: &keys,
                threshold: schedule.threshold(),
                now_ts: 1_000_010,
                ttl_secs: 300,
                remote_ip: None,
                peer_id: None,
                puzzle_id: "client1",
                puzzles: &mut puzzles,
                rate_limiter: &mut rate_limiter,
                replay: &replay,
                spend_verifier: &verifier,
                trust_anchors: &vkd_keys.trust,
                last_verified_sth: None,
            },
            ResponderSession {
                message: &m1_retry,
                directory: &record,
                state: &mut bob_state,
            },
        )
        .unwrap();

        let keys = schedule.active_keys(1_000_020);
        assert!(matches!(
            responder_handshake_resp::<MlKem1024>(
                ResponderEnv {
                    keys: &keys,
                    threshold: schedule.threshold(),
                    now_ts: 1_000_020,
                    ttl_secs: 300,
                    remote_ip: None,
                    peer_id: None,
                    puzzle_id: "client1",
                    puzzles: &mut puzzles,
                    rate_limiter: &mut rate_limiter,
                    replay: &replay,
                    spend_verifier: &verifier,
                    trust_anchors: &vkd_keys.trust,
                    last_verified_sth: None,
                },
                ResponderSession {
                    message: &m1_retry,
                    directory: &record,
                    state: &mut bob_state,
                }
            ),
            Err(HandshakeError::Replay)
        ));

        let vkd2 = make_vkd_proof(&record, &vkd_keys);
        let (m1b, _) =
            initiator_handshake_init::<MlKem1024>(&record, spend.clone(), None, vkd2).unwrap();
        let keys = schedule.active_keys(1_000_030);
        let retry2 = match responder_handshake_resp::<MlKem1024>(
            ResponderEnv {
                keys: &keys,
                threshold: schedule.threshold(),
                now_ts: 1_000_030,
                ttl_secs: 300,
                remote_ip: None,
                peer_id: None,
                puzzle_id: "client1",
                puzzles: &mut puzzles,
                rate_limiter: &mut rate_limiter,
                replay: &replay,
                spend_verifier: &verifier,
                trust_anchors: &vkd_keys.trust,
                last_verified_sth: None,
            },
            ResponderSession {
                message: &m1b,
                directory: &record,
                state: &mut bob_state,
            },
        ) {
            Err(HandshakeError::Retry(c)) => c,
            _ => panic!("expected retry"),
        };
        let mut solved2 = retry2.clone();
        solved2.nonce = solve_puzzle(&solved2.puzzle);
        let mut m1b_retry = m1b.clone();
        m1b_retry.cookie = Some(solved2);
        let quorum_digest = hash_quorum_descriptor(&record.quorum_desc).unwrap();
        m1b_retry.transcript_bind = compute_transcript_bind_v2(TranscriptBindContext {
            eph_x25519_pub: &m1b_retry.eph_x25519_pub,
            x25519_prekey: &record.x25519_prekey,
            kem_ciphertext: &m1b_retry.kem_ciphertext,
            did: &m1b_retry.did,
            epoch: m1b_retry.epoch,
            prekey_batch_root: &m1b_retry.prekey_batch_root,
            spend: &m1b_retry.spend,
            sth_cid: &m1b_retry.sth_cid,
            bundle_cid: &m1b_retry.bundle_cid,
            quorum_desc_digest: &quorum_digest,
            vkd: &m1b_retry.vkd_proof,
            pad: &m1b_retry.pad,
            cookie: m1b_retry.cookie.as_ref(),
        });
        let keys = schedule.active_keys(1_000_040);
        assert!(matches!(
            responder_handshake_resp::<MlKem1024>(
                ResponderEnv {
                    keys: &keys,
                    threshold: schedule.threshold(),
                    now_ts: 1_000_040,
                    ttl_secs: 300,
                    remote_ip: None,
                    peer_id: None,
                    puzzle_id: "client1",
                    puzzles: &mut puzzles,
                    rate_limiter: &mut rate_limiter,
                    replay: &replay,
                    spend_verifier: &verifier,
                    trust_anchors: &vkd_keys.trust,
                    last_verified_sth: None,
                },
                ResponderSession {
                    message: &m1b_retry,
                    directory: &record,
                    state: &mut bob_state,
                }
            ),
            Err(HandshakeError::TokenUsed)
        ));
    }

    #[test]
    fn bind_tamper_detects() {
        let (record, mut bob_state) = generate_directory_record::<MlKem1024>(
            b"did:example".to_vec(),
            1,
            sample_quorum_desc(1),
        )
        .unwrap();
        let spend = make_receipt(record.prekey_batch_root);
        let replay = TestReplay::default();
        let verifier = TestSpendVerifier::default();
        let server_secret = [9u8; 32];
        let mut schedule = KeySchedule::new(2, 3, u64::MAX);
        schedule.rotate(&server_secret, COOKIE_FMT_V1, 0);
        let mut puzzles = AdaptivePuzzleDifficulty::new(4, 8);
        let mut rate_limiter = RateLimiter::unlimited();
        let vkd_keys = TestVkdKeys::single_witness();
        let vkd = make_vkd_proof(&record, &vkd_keys);
        let (m1, _) =
            initiator_handshake_init::<MlKem1024>(&record, spend.clone(), None, vkd).unwrap();
        let keys = schedule.active_keys(1_000_000);
        let retry = match responder_handshake_resp::<MlKem1024>(
            ResponderEnv {
                keys: &keys,
                threshold: schedule.threshold(),
                now_ts: 1_000_000,
                ttl_secs: 300,
                remote_ip: None,
                peer_id: None,
                puzzle_id: "client1",
                puzzles: &mut puzzles,
                rate_limiter: &mut rate_limiter,
                replay: &replay,
                spend_verifier: &verifier,
                trust_anchors: &vkd_keys.trust,
                last_verified_sth: None,
            },
            ResponderSession {
                message: &m1,
                directory: &record,
                state: &mut bob_state,
            },
        ) {
            Err(HandshakeError::Retry(c)) => c,
            _ => panic!("expected retry"),
        };
        let mut solved = retry.clone();
        solved.nonce = solve_puzzle(&solved.puzzle);
        let mut m1_tamper = m1.clone();
        m1_tamper.cookie = Some(solved);
        let quorum_digest = hash_quorum_descriptor(&record.quorum_desc).unwrap();
        m1_tamper.transcript_bind = compute_transcript_bind_v2(TranscriptBindContext {
            eph_x25519_pub: &m1_tamper.eph_x25519_pub,
            x25519_prekey: &record.x25519_prekey,
            kem_ciphertext: &m1_tamper.kem_ciphertext,
            did: &m1_tamper.did,
            epoch: m1_tamper.epoch,
            prekey_batch_root: &m1_tamper.prekey_batch_root,
            spend: &m1_tamper.spend,
            sth_cid: &m1_tamper.sth_cid,
            bundle_cid: &m1_tamper.bundle_cid,
            quorum_desc_digest: &quorum_digest,
            vkd: &m1_tamper.vkd_proof,
            pad: &m1_tamper.pad,
            cookie: m1_tamper.cookie.as_ref(),
        });
        m1_tamper.transcript_bind[0] ^= 1;
        let keys = schedule.active_keys(1_000_010);
        assert!(matches!(
            responder_handshake_resp::<MlKem1024>(
                ResponderEnv {
                    keys: &keys,
                    threshold: schedule.threshold(),
                    now_ts: 1_000_010,
                    ttl_secs: 300,
                    remote_ip: None,
                    peer_id: None,
                    puzzle_id: "client1",
                    puzzles: &mut puzzles,
                    rate_limiter: &mut rate_limiter,
                    replay: &replay,
                    spend_verifier: &verifier,
                    trust_anchors: &vkd_keys.trust,
                    last_verified_sth: None,
                },
                ResponderSession {
                    message: &m1_tamper,
                    directory: &record,
                    state: &mut bob_state,
                }
            ),
            Err(HandshakeError::Generic)
        ));
    }

    #[test]
    fn key_revocation_rollover() {
        let secret1 = [1u8; 32];
        let secret2 = [2u8; 32];
        let mut schedule = KeySchedule::new(2, 3, 20);
        schedule.rotate(&secret1, 1, 0);
        let ctx = b"abc".to_vec();
        let keys = schedule.active_keys(10);
        let mut cookie = make_retry_cookie(
            &keys[0].shares,
            schedule.threshold(),
            keys[0].key_id,
            &ctx,
            10,
            4,
        )
        .unwrap();
        cookie.nonce = solve_puzzle(&cookie.puzzle);
        schedule.rotate(&secret2, 2, 20);
        let keys_overlap = schedule.active_keys(25);
        assert!(keys_overlap.iter().any(|k| {
            verify_retry_cookie(
                &k.shares,
                schedule.threshold(),
                k.key_id,
                &ctx,
                25,
                300,
                &cookie,
            )
            .unwrap()
        }));
        let keys_revoked = schedule.active_keys(45);
        assert!(!keys_revoked.iter().any(|k| {
            verify_retry_cookie(
                &k.shares,
                schedule.threshold(),
                k.key_id,
                &ctx,
                45,
                300,
                &cookie,
            )
            .unwrap()
        }));
    }

    #[test]
    fn tofu_pinning_detects_changes() {
        let (bundle1, _) = generate_directory_record::<MlKem1024>(
            b"did:example".to_vec(),
            1,
            sample_quorum_desc(1),
        )
        .unwrap();
        let fp1 = record_fingerprint(&bundle1);
        assert!(matches!(
            verify_record_pin::<MlKem1024>(None, &bundle1, None),
            PinStatus::FirstUse(_)
        ));
        assert!(matches!(
            verify_record_pin::<MlKem1024>(Some(fp1), &bundle1, None),
            PinStatus::Match
        ));
        let (bundle2, _) = generate_directory_record::<MlKem1024>(
            b"did:example".to_vec(),
            1,
            sample_quorum_desc(1),
        )
        .unwrap();
        let warning = std::sync::Mutex::new(String::new());
        let status = verify_record_pin::<MlKem1024>(
            Some(fp1),
            &bundle2,
            Some(&|msg| *warning.lock().unwrap() = msg.to_string()),
        );
        assert!(matches!(status, PinStatus::Changed(_)));
        assert!(!warning.lock().unwrap().is_empty());
    }

    #[test]
    fn multi_pin_first_contact() {
        let (b1, _) = generate_directory_record::<MlKem1024>(
            b"did:example".to_vec(),
            1,
            sample_quorum_desc(1),
        )
        .unwrap();
        let (b2, _) = generate_directory_record::<MlKem1024>(
            b"did:example".to_vec(),
            1,
            sample_quorum_desc(1),
        )
        .unwrap();
        match verify_record_pin_multi::<MlKem1024>(None, &[b1.clone(), b2.clone()]) {
            MultiPinStatus::FirstUse(fps) => assert_eq!(fps.len(), 2),
            _ => panic!("expected first-use"),
        }
        let p = record_fingerprint(&b1);
        assert!(matches!(
            verify_record_pin_multi::<MlKem1024>(Some(vec![p]), std::slice::from_ref(&b1)),
            MultiPinStatus::Match
        ));
        assert!(matches!(
            verify_record_pin_multi::<MlKem1024>(Some(vec![p]), &[b2]),
            MultiPinStatus::Changed(_)
        ));
    }

    #[test]
    fn pin_persistence_roundtrip() {
        let pins = vec![[1u8; 32], [2u8; 32]];
        let path = std::env::temp_dir().join("pins_test.txt");
        save_pins(&path, &pins).unwrap();
        let loaded = load_pins(&path).unwrap().unwrap();
        assert_eq!(pins, loaded);
        std::fs::remove_file(path).unwrap();
    }

    fn random_peer_id() -> PeerId {
        let kp = Keypair::generate_ed25519();
        PeerId::from_public_key(&kp.public())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(3))]
        #[test]
        fn rate_limiter_throttles_attackers_and_allows_legit(
            attacker_attempts in 2usize..5,
            refill_secs in 1u64..5,
        ) {
            use std::net::{IpAddr, Ipv4Addr};

            let (record, mut responder_state) =
                generate_directory_record::<MlKem1024>(
                    b"did:example".to_vec(),
                    1,
                    sample_quorum_desc(1),
                )
                .unwrap();
            let replay = TestReplay::default();
            let verifier = TestSpendVerifier::default();
            let server_secret = [9u8; 32];
            let mut schedule = KeySchedule::new(2, 3, u64::MAX);
            schedule.rotate(&server_secret, COOKIE_FMT_V1, 0);
            let mut puzzles = AdaptivePuzzleDifficulty::new(4, 8);
            let mut rate_limiter = RateLimiter::new(
                RateLimitParams::new(1, 1, refill_secs),
                RateLimitParams::new(1, 1, refill_secs),
            );
            let ip = IpAddr::from(Ipv4Addr::new(198, 51, 100, 1));
            let peer = random_peer_id();
            let mut now = 1_000_000u64;
            let vkd_keys = TestVkdKeys::single_witness();

            let mut throttled = false;
            for _ in 0..attacker_attempts {
                let spend = make_receipt(record.prekey_batch_root);
                let vkd = make_vkd_proof(&record, &vkd_keys);
                let (mut m1, _) =
                initiator_handshake_init::<MlKem1024>(&record, spend, None, vkd).unwrap();

                let keys = schedule.active_keys(now);
                let mut scratch_state = responder_state.clone();
                let retry = match responder_handshake_resp::<MlKem1024>(
                    ResponderEnv {
                        keys: &keys,
                        threshold: schedule.threshold(),
                        now_ts: now,
                        ttl_secs: 300,
                        remote_ip: Some(ip),
                        peer_id: Some(&peer),
                        puzzle_id: "client1",
                        puzzles: &mut puzzles,
                        rate_limiter: &mut rate_limiter,
                        replay: &replay,
                        spend_verifier: &verifier,
                        trust_anchors: &vkd_keys.trust,
                        last_verified_sth: None,
                    },
                    ResponderSession {
                        message: &m1,
                        directory: &record,
                        state: &mut scratch_state,
                    },
                ) {
                    Err(HandshakeError::Retry(c)) => c,
                    _ => panic!("expected retry without cookie"),
                };

                let mut solved = retry.clone();
                solved.nonce = solve_puzzle(&solved.puzzle);
                m1.cookie = Some(solved);
                let quorum_digest = hash_quorum_descriptor(&record.quorum_desc).unwrap();
                m1.transcript_bind = compute_transcript_bind_v2(TranscriptBindContext {
                    eph_x25519_pub: &m1.eph_x25519_pub,
                    x25519_prekey: &record.x25519_prekey,
                    kem_ciphertext: &m1.kem_ciphertext,
                    did: &m1.did,
                    epoch: m1.epoch,
                    prekey_batch_root: &m1.prekey_batch_root,
                    spend: &m1.spend,
                    sth_cid: &m1.sth_cid,
                    bundle_cid: &m1.bundle_cid,
                    quorum_desc_digest: &quorum_digest,
                    vkd: &m1.vkd_proof,
                    pad: &m1.pad,
                    cookie: m1.cookie.as_ref(),
                });

                let mut temp_state = responder_state.clone();
                let keys = schedule.active_keys(now);
                match responder_handshake_resp::<MlKem1024>(
                    ResponderEnv {
                        keys: &keys,
                        threshold: schedule.threshold(),
                        now_ts: now,
                        ttl_secs: 300,
                        remote_ip: Some(ip),
                        peer_id: Some(&peer),
                        puzzle_id: "client1",
                        puzzles: &mut puzzles,
                        rate_limiter: &mut rate_limiter,
                        replay: &replay,
                        spend_verifier: &verifier,
                        trust_anchors: &vkd_keys.trust,
                        last_verified_sth: None,
                    },
                    ResponderSession {
                        message: &m1,
                        directory: &record,
                        state: &mut temp_state,
                    },
                ) {
                    Err(HandshakeError::Retry(_)) => {
                        throttled = true;
                        break;
                    }
                    Ok(_) => {
                        continue;
                    }
                    Err(_) => panic!("unexpected handshake error"),
                }
            }
            prop_assert!(throttled, "attackers never reached throttle");
            let escalated = puzzles.current("client1");
            prop_assert!(escalated >= 5, "puzzle difficulty should increase");

            now += refill_secs.saturating_mul(2);
            let spend = make_receipt(record.prekey_batch_root);
            let vkd = make_vkd_proof(&record, &vkd_keys);
            let (mut legit_m1, _) =
                initiator_handshake_init::<MlKem1024>(&record, spend, None, vkd).unwrap();
            let keys = schedule.active_keys(now);
            let mut scratch_state = responder_state.clone();
            let retry = match responder_handshake_resp::<MlKem1024>(
                ResponderEnv {
                    keys: &keys,
                    threshold: schedule.threshold(),
                    now_ts: now,
                    ttl_secs: 300,
                    remote_ip: Some(ip),
                    peer_id: Some(&peer),
                    puzzle_id: "client1",
                    puzzles: &mut puzzles,
                    rate_limiter: &mut rate_limiter,
                    replay: &replay,
                    spend_verifier: &verifier,
                    trust_anchors: &vkd_keys.trust,
                    last_verified_sth: None,
                },
                ResponderSession {
                    message: &legit_m1,
                    directory: &record,
                    state: &mut scratch_state,
                },
            ) {
                Err(HandshakeError::Retry(c)) => c,
                _ => panic!("expected retry to mint cookie"),
            };
            let mut solved = retry.clone();
            solved.nonce = solve_puzzle(&solved.puzzle);
            legit_m1.cookie = Some(solved);
            let quorum_digest = hash_quorum_descriptor(&record.quorum_desc).unwrap();
            legit_m1.transcript_bind = compute_transcript_bind_v2(TranscriptBindContext {
                eph_x25519_pub: &legit_m1.eph_x25519_pub,
                x25519_prekey: &record.x25519_prekey,
                kem_ciphertext: &legit_m1.kem_ciphertext,
                did: &legit_m1.did,
                epoch: legit_m1.epoch,
                prekey_batch_root: &legit_m1.prekey_batch_root,
                spend: &legit_m1.spend,
                sth_cid: &legit_m1.sth_cid,
                bundle_cid: &legit_m1.bundle_cid,
                quorum_desc_digest: &quorum_digest,
                vkd: &legit_m1.vkd_proof,
                pad: &legit_m1.pad,
                cookie: legit_m1.cookie.as_ref(),
            });
            let before_success = puzzles.current("client1");
            let keys = schedule.active_keys(now);
            let (_resp, _, _, _) = responder_handshake_resp::<MlKem1024>(
                ResponderEnv {
                    keys: &keys,
                    threshold: schedule.threshold(),
                    now_ts: now,
                    ttl_secs: 300,
                    remote_ip: Some(ip),
                    peer_id: Some(&peer),
                    puzzle_id: "client1",
                    puzzles: &mut puzzles,
                    rate_limiter: &mut rate_limiter,
                    replay: &replay,
                    spend_verifier: &verifier,
                    trust_anchors: &vkd_keys.trust,
                    last_verified_sth: None,
                },
                ResponderSession {
                    message: &legit_m1,
                    directory: &record,
                    state: &mut responder_state,
                },
            )
            .expect("legitimate client should succeed after solving the cookie");
            prop_assert_eq!(
                puzzles.current("client1"),
                before_success.saturating_sub(1),
                "puzzle difficulty should relax after success",
            );
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1))]
        #[test]
        fn nonce_derivation_no_collisions(
            hhs in proptest::collection::vec(any::<[u8; 32]>(), 10_000)
        ) {
            let mut set2 = HashSet::new();
            let mut set3 = HashSet::new();
            let mut set4 = HashSet::new();
            for hh in hhs {
                let n2 = hkdf_n12(&hh, &[ROLE_R, 2]);
                let n3 = hkdf_n12(&hh, &[ROLE_I, 3]);
                let n4 = hkdf_n12(&hh, &[ROLE_R, 4]);
                prop_assert!(set2.insert(n2));
                prop_assert!(set3.insert(n3));
                prop_assert!(set4.insert(n4));
            }
        }
    }
}
