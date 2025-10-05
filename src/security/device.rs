use std::collections::{HashMap, VecDeque};
use std::marker::PhantomData;
use std::time::{Duration, Instant};

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use libp2p_identity::ed25519;
use rand_core_06::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::security::audit::SharedSecret;
use crate::CryptoError;
use crate::Kem;

/// Provides the public identity used to validate device certificates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MasterIdentity {
    key: ed25519::PublicKey,
}

impl MasterIdentity {
    /// Creates a new [`MasterIdentity`] from an Ed25519 public key.
    pub fn new(key: ed25519::PublicKey) -> Self {
        Self { key }
    }

    /// Returns the underlying Ed25519 public key.
    pub fn public_key(&self) -> &ed25519::PublicKey {
        &self.key
    }
}

/// Holder of the offline master signing key.
#[derive(Clone)]
pub struct MasterSigningKey {
    keypair: ed25519::Keypair,
}

impl MasterSigningKey {
    /// Constructs a [`MasterSigningKey`] from the provided keypair.
    pub fn new(keypair: ed25519::Keypair) -> Self {
        Self { keypair }
    }

    /// Returns the public identity associated with this master key.
    pub fn identity(&self) -> MasterIdentity {
        MasterIdentity::new(self.keypair.public())
    }

    /// Signs a device certificate body, producing a fully bound certificate.
    pub fn sign(
        &self,
        body: DeviceCertificateBody,
    ) -> Result<DeviceCertificate, DeviceRegistryError> {
        let payload = body.signing_payload()?;
        let signature = self.keypair.sign(&payload);
        Ok(DeviceCertificate { body, signature })
    }

    /// Signs an [`AuditBody`] describing a critical VKD operation.
    pub fn sign_audit(&self, body: AuditBody) -> Result<AuditProof, DeviceRegistryError> {
        let payload = serde_cbor::to_vec(&body)
            .map_err(|error| DeviceRegistryError::Serialization(error.to_string()))?;
        let signature = self.keypair.sign(&payload);
        Ok(AuditProof { body, signature })
    }
}

/// Optional device attestation metadata embedded within certificates.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Attestation {
    kind: AttestationKind,
    statement: Vec<u8>,
    expires_at: u64,
}

impl Attestation {
    /// Builds a new attestation statement.
    pub fn new(kind: AttestationKind, statement: Vec<u8>, expires_at: u64) -> Self {
        Self {
            kind,
            statement,
            expires_at,
        }
    }

    /// Returns the attestation kind.
    pub fn kind(&self) -> &AttestationKind {
        &self.kind
    }

    /// Returns the raw attestation payload.
    pub fn statement(&self) -> &[u8] {
        &self.statement
    }

    /// Returns the attestation expiry timestamp (seconds since epoch).
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Indicates whether the attestation is still valid relative to `now`.
    pub fn is_fresh(&self, now: u64) -> bool {
        now <= self.expires_at
    }
}

/// Enumeration of supported attestation token formats.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AttestationKind {
    AndroidSafetyNet,
    AppleDeviceCheck,
    Tpm,
    Custom(String),
}

/// Unsigned portion of a device certificate that is covered by the master signature.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceCertificateBody {
    device_id: Uuid,
    issued_at: u64,
    expires_at: u64,
    kem_public_key: Vec<u8>,
    x25519_public_key: [u8; 32],
    attestation: Option<Attestation>,
}

impl DeviceCertificateBody {
    /// Constructs a new certificate body with the given parameters.
    pub fn new(
        device_id: Uuid,
        issued_at: u64,
        expires_at: u64,
        kem_public_key: Vec<u8>,
        x25519_public_key: [u8; 32],
        attestation: Option<Attestation>,
    ) -> Self {
        Self {
            device_id,
            issued_at,
            expires_at,
            kem_public_key,
            x25519_public_key,
            attestation,
        }
    }

    fn signing_payload(&self) -> Result<Vec<u8>, DeviceRegistryError> {
        serde_cbor::to_vec(self)
            .map_err(|error| DeviceRegistryError::Serialization(error.to_string()))
    }

    fn validate_lifetime(&self, now: u64, max_lifetime: u64) -> Result<(), DeviceRegistryError> {
        if self.issued_at > now + MAX_FUTURE_SKEW_SECS {
            return Err(DeviceRegistryError::NotYetValid {
                now,
                issued_at: self.issued_at,
            });
        }
        if self.expires_at <= self.issued_at {
            return Err(DeviceRegistryError::InvalidLifetime {
                issued_at: self.issued_at,
                expires_at: self.expires_at,
                max_lifetime,
            });
        }
        let lifetime = self.expires_at.saturating_sub(self.issued_at);
        if lifetime > max_lifetime {
            return Err(DeviceRegistryError::InvalidLifetime {
                issued_at: self.issued_at,
                expires_at: self.expires_at,
                max_lifetime,
            });
        }
        if now > self.expires_at {
            return Err(DeviceRegistryError::Expired {
                now,
                expires_at: self.expires_at,
            });
        }
        if let Some(attestation) = &self.attestation {
            if !attestation.is_fresh(now) {
                return Err(DeviceRegistryError::StaleAttestation {
                    expires_at: attestation.expires_at(),
                    now,
                });
            }
        }
        Ok(())
    }
}

const MAX_FUTURE_SKEW_SECS: u64 = 300;
const ZERO_HASH: [u8; 32] = [0u8; 32];

/// Master-signed certificate proving device enrollment.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceCertificate {
    body: DeviceCertificateBody,
    signature: Vec<u8>,
}

impl DeviceCertificate {
    /// Returns the certificate body.
    pub fn body(&self) -> &DeviceCertificateBody {
        &self.body
    }

    /// Returns the signed device identifier.
    pub fn device_id(&self) -> Uuid {
        self.body.device_id
    }

    /// Computes a stable fingerprint over the signed certificate body.
    pub fn fingerprint(&self) -> Result<[u8; 32], DeviceRegistryError> {
        let payload = self.body.signing_payload()?;
        let digest = Sha256::digest(&payload);
        let mut fingerprint = [0u8; 32];
        fingerprint.copy_from_slice(&digest);
        Ok(fingerprint)
    }

    /// Returns the certificate expiry timestamp.
    pub fn expires_at(&self) -> u64 {
        self.body.expires_at
    }

    /// Returns the certificate issuance timestamp.
    pub fn issued_at(&self) -> u64 {
        self.body.issued_at
    }

    /// Verifies the certificate signature against the provided master identity.
    pub fn verify(&self, master: &MasterIdentity) -> Result<(), DeviceRegistryError> {
        let payload = self.body.signing_payload()?;
        if master.public_key().verify(&payload, &self.signature) {
            Ok(())
        } else {
            Err(DeviceRegistryError::SignatureInvalid)
        }
    }
}

/// Reason explaining why a device was revoked at a specific epoch.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum RevocationReason {
    UserInitiated,
    SuspiciousBehavior,
    DeviceLost,
    CompromiseDetected,
    Expired,
}

/// Metadata describing a device revocation entry published in the VKD.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevocationEntry {
    epoch: u64,
    reason: RevocationReason,
}

impl RevocationEntry {
    /// Builds a new revocation entry.
    pub fn new(epoch: u64, reason: RevocationReason) -> Self {
        Self { epoch, reason }
    }

    /// Returns the VKD epoch in which the revocation was published.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns the reason associated with the revocation.
    pub fn reason(&self) -> &RevocationReason {
        &self.reason
    }
}

/// VKD-backed announcement covering device additions, revocations, or master rotations.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuditOperation {
    DeviceAdd {
        device_id: Uuid,
        cert_fingerprint: [u8; 32],
    },
    DeviceRevoke {
        device_ids: Vec<Uuid>,
        reason: RevocationReason,
    },
    MasterRotate {
        new_master_key: [u8; 32],
    },
}

/// Unsigned body describing a critical VKD operation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditBody {
    epoch: u64,
    prev_epoch_hash: [u8; 32],
    epoch_hash: [u8; 32],
    operation: AuditOperation,
    vrf_output: Option<Vec<u8>>,
}

impl AuditBody {
    /// Constructs a new audit body.
    pub fn new(
        epoch: u64,
        prev_epoch_hash: [u8; 32],
        epoch_hash: [u8; 32],
        operation: AuditOperation,
        vrf_output: Option<Vec<u8>>,
    ) -> Self {
        Self {
            epoch,
            prev_epoch_hash,
            epoch_hash,
            operation,
            vrf_output,
        }
    }
}

/// Signed proof that a VKD epoch executed a critical operation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditProof {
    body: AuditBody,
    signature: Vec<u8>,
}

impl AuditProof {
    /// Returns the epoch where the operation was committed.
    pub fn epoch(&self) -> u64 {
        self.body.epoch
    }

    /// Returns the hash of the previous epoch referenced by this proof.
    pub fn prev_epoch_hash(&self) -> &[u8; 32] {
        &self.body.prev_epoch_hash
    }

    /// Returns the hash of the epoch that produced this proof.
    pub fn epoch_hash(&self) -> &[u8; 32] {
        &self.body.epoch_hash
    }

    /// Returns the announced operation.
    pub fn operation(&self) -> &AuditOperation {
        &self.body.operation
    }

    /// Returns the optional VRF output carried with the proof.
    pub fn vrf_output(&self) -> Option<&[u8]> {
        self.body.vrf_output.as_deref()
    }

    /// Verifies the proof signature against the supplied master identity.
    pub fn verify_signature(&self, identity: &MasterIdentity) -> Result<(), AuditError> {
        let payload = serde_cbor::to_vec(&self.body)
            .map_err(|error| AuditError::Serialization(error.to_string()))?;
        if identity.public_key().verify(&payload, &self.signature) {
            Ok(())
        } else {
            Err(AuditError::InvalidSignature)
        }
    }
}

/// Errors raised when validating audit proofs.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuditError {
    #[error("audit serialization error: {0}")]
    Serialization(String),
    #[error("audit signature invalid")]
    InvalidSignature,
    #[error("audit previous hash mismatch (expected={expected:?}, actual={actual:?})")]
    PrevHashMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    #[error("audit epoch regression (last={last_epoch}, attempted={attempted})")]
    EpochRollback { last_epoch: u64, attempted: u64 },
    #[error("audit operation mismatch (expected={expected}, actual={actual:?})")]
    OperationMismatch {
        expected: &'static str,
        actual: AuditOperation,
    },
}

/// Errors encountered when managing the device registry.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DeviceRegistryError {
    #[error("device certificate not yet valid (now={now}, issued_at={issued_at})")]
    NotYetValid { now: u64, issued_at: u64 },
    #[error("device certificate expired (now={now}, expires_at={expires_at})")]
    Expired { now: u64, expires_at: u64 },
    #[error("device lifetime invalid (issued_at={issued_at}, expires_at={expires_at}, max={max_lifetime})")]
    InvalidLifetime {
        issued_at: u64,
        expires_at: u64,
        max_lifetime: u64,
    },
    #[error("device certificate signature invalid")]
    SignatureInvalid,
    #[error("revocation epoch regression detected (last={last_epoch}, attempted={attempted})")]
    EpochRollback { last_epoch: u64, attempted: u64 },
    #[error("device has been revoked at epoch {epoch} for reason {reason:?}")]
    Revoked {
        epoch: u64,
        reason: RevocationReason,
    },
    #[error("device not registered")]
    UnknownDevice,
    #[error(
        "device certificate replaced with stale issuance (existing={existing}, new={new_issue})"
    )]
    StaleUpdate { existing: u64, new_issue: u64 },
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("attestation expired (expires_at={expires_at}, now={now})")]
    StaleAttestation { expires_at: u64, now: u64 },
    #[error("audit validation failed: {0}")]
    Audit(#[from] AuditError),
    #[error("invalid master key material: {0}")]
    InvalidMasterKey(String),
}

/// Tracks device certificates, expirations, and revocations validated against VKD epochs.
pub struct DeviceRegistry {
    master: MasterIdentity,
    max_lifetime: u64,
    certificates: HashMap<Uuid, DeviceCertificate>,
    revocations: HashMap<Uuid, RevocationEntry>,
    last_revocation_epoch: u64,
    last_audit_epoch: u64,
    last_epoch_hash: Option<[u8; 32]>,
}

impl DeviceRegistry {
    /// Builds a new registry with the configured maximum certificate lifetime in seconds.
    pub fn new(master: MasterIdentity, max_lifetime: Duration) -> Self {
        let max_lifetime = max_lifetime.as_secs().max(1);
        Self {
            master,
            max_lifetime,
            certificates: HashMap::new(),
            revocations: HashMap::new(),
            last_revocation_epoch: 0,
            last_audit_epoch: 0,
            last_epoch_hash: None,
        }
    }

    fn check_audit_chain(&self, audit: &AuditProof) -> Result<(), DeviceRegistryError> {
        if audit.epoch() <= self.last_audit_epoch {
            return Err(AuditError::EpochRollback {
                last_epoch: self.last_audit_epoch,
                attempted: audit.epoch(),
            }
            .into());
        }
        let expected_prev = self.last_epoch_hash.unwrap_or(ZERO_HASH);
        if audit.prev_epoch_hash() != &expected_prev {
            return Err(AuditError::PrevHashMismatch {
                expected: expected_prev,
                actual: *audit.prev_epoch_hash(),
            }
            .into());
        }
        Ok(())
    }

    fn advance_audit_chain(&mut self, audit: &AuditProof) {
        self.last_audit_epoch = audit.epoch();
        self.last_epoch_hash = Some(*audit.epoch_hash());
    }

    /// Registers or renews a device certificate after verifying audit proofs and expiry.
    pub fn register(
        &mut self,
        cert: DeviceCertificate,
        audit: AuditProof,
        now: u64,
    ) -> Result<(), DeviceRegistryError> {
        audit.verify_signature(&self.master)?;
        self.check_audit_chain(&audit)?;
        let device_id = cert.device_id();
        let fingerprint = cert.fingerprint()?;
        match audit.operation() {
            AuditOperation::DeviceAdd {
                device_id: announced_id,
                cert_fingerprint,
            } => {
                if announced_id != &device_id || cert_fingerprint != &fingerprint {
                    return Err(AuditError::OperationMismatch {
                        expected: "DeviceAdd",
                        actual: audit.operation().clone(),
                    }
                    .into());
                }
            }
            _ => {
                return Err(AuditError::OperationMismatch {
                    expected: "DeviceAdd",
                    actual: audit.operation().clone(),
                }
                .into());
            }
        }
        cert.verify(&self.master)?;
        cert.body.validate_lifetime(now, self.max_lifetime)?;
        if let Some(existing) = self.certificates.get(&device_id) {
            if existing.issued_at() > cert.issued_at() {
                return Err(DeviceRegistryError::StaleUpdate {
                    existing: existing.issued_at(),
                    new_issue: cert.issued_at(),
                });
            }
        }
        if let Some(revoked) = self.revocations.get(&device_id) {
            return Err(DeviceRegistryError::Revoked {
                epoch: revoked.epoch(),
                reason: revoked.reason().clone(),
            });
        }
        self.certificates.insert(device_id, cert);
        self.advance_audit_chain(&audit);
        Ok(())
    }

    /// Marks a set of devices as revoked using a VKD-backed audit proof.
    pub fn revoke_devices(&mut self, audit: AuditProof) -> Result<(), DeviceRegistryError> {
        audit.verify_signature(&self.master)?;
        self.check_audit_chain(&audit)?;
        let (device_ids, reason) = match audit.operation() {
            AuditOperation::DeviceRevoke { device_ids, reason } => {
                (device_ids.clone(), reason.clone())
            }
            _ => {
                return Err(AuditError::OperationMismatch {
                    expected: "DeviceRevoke",
                    actual: audit.operation().clone(),
                }
                .into());
            }
        };
        if device_ids.is_empty() {
            return Err(AuditError::OperationMismatch {
                expected: "DeviceRevoke",
                actual: audit.operation().clone(),
            }
            .into());
        }
        for device_id in &device_ids {
            self.revocations.insert(
                *device_id,
                RevocationEntry::new(audit.epoch(), reason.clone()),
            );
            self.certificates.remove(device_id);
        }
        self.last_revocation_epoch = audit.epoch();
        self.advance_audit_chain(&audit);
        Ok(())
    }

    /// Returns the current master identity used for certificate validation.
    pub fn master_identity(&self) -> &MasterIdentity {
        &self.master
    }

    /// Rotates the master identity using a signed VKD audit proof.
    pub fn rotate_master(&mut self, audit: AuditProof) -> Result<(), DeviceRegistryError> {
        audit.verify_signature(&self.master)?;
        self.check_audit_chain(&audit)?;
        let new_master_bytes = match audit.operation() {
            AuditOperation::MasterRotate { new_master_key } => *new_master_key,
            _ => {
                return Err(AuditError::OperationMismatch {
                    expected: "MasterRotate",
                    actual: audit.operation().clone(),
                }
                .into());
            }
        };
        let new_master = ed25519::PublicKey::try_from_bytes(&new_master_bytes)
            .map_err(|error| DeviceRegistryError::InvalidMasterKey(error.to_string()))?;
        self.master = MasterIdentity::new(new_master);
        self.certificates.clear();
        self.advance_audit_chain(&audit);
        self.last_revocation_epoch = self.last_revocation_epoch.max(audit.epoch());
        Ok(())
    }

    /// Removes expired certificates from the registry and records them as revoked.
    pub fn prune_expired(&mut self, now: u64, epoch: u64) {
        let mut expired = Vec::new();
        for (id, cert) in &self.certificates {
            if cert.expires_at() <= now {
                expired.push(*id);
            }
        }
        for id in expired {
            self.certificates.remove(&id);
            self.revocations
                .insert(id, RevocationEntry::new(epoch, RevocationReason::Expired));
        }
        if epoch > self.last_revocation_epoch {
            self.last_revocation_epoch = epoch;
        }
    }

    /// Returns whether a device is currently trusted for new sessions.
    pub fn is_trusted(
        &self,
        device_id: &Uuid,
        now: u64,
    ) -> Result<&DeviceCertificate, DeviceRegistryError> {
        if let Some(revocation) = self.revocations.get(device_id) {
            return Err(DeviceRegistryError::Revoked {
                epoch: revocation.epoch(),
                reason: revocation.reason().clone(),
            });
        }
        let cert = self
            .certificates
            .get(device_id)
            .ok_or(DeviceRegistryError::UnknownDevice)?;
        if cert.expires_at() <= now {
            return Err(DeviceRegistryError::Expired {
                now,
                expires_at: cert.expires_at(),
            });
        }
        Ok(cert)
    }

    /// Retrieves the revocation metadata for the specified device, if any.
    pub fn revocation(&self, device_id: &Uuid) -> Option<&RevocationEntry> {
        self.revocations.get(device_id)
    }

    /// Returns the number of currently active device certificates.
    pub fn active_count(&self) -> usize {
        self.certificates.len()
    }
}

/// One-time asynchronous prekey descriptor published in the VKD.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AsyncPrekey {
    id: Uuid,
    kem_public_key: Vec<u8>,
    x25519_public_key: [u8; 32],
    expires_at: u64,
}

impl AsyncPrekey {
    /// Constructs a new asynchronous prekey record.
    pub fn new(
        id: Uuid,
        kem_public_key: Vec<u8>,
        x25519_public_key: [u8; 32],
        expires_at: u64,
    ) -> Self {
        Self {
            id,
            kem_public_key,
            x25519_public_key,
            expires_at,
        }
    }

    /// Returns the prekey identifier.
    pub fn id(&self) -> Uuid {
        self.id
    }

    /// Returns the expiry timestamp.
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Provides the serialized ML-KEM public key bytes.
    pub fn kem_public_key(&self) -> &[u8] {
        &self.kem_public_key
    }

    /// Provides the X25519 public key bytes.
    pub fn x25519_public_key(&self) -> &[u8; 32] {
        &self.x25519_public_key
    }
}

/// Errors raised by [`PrekeyQueue`] operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PrekeyError {
    #[error("prekey queue is at capacity")]
    QueueFull,
    #[error("prekey not found")]
    UnknownPrekey,
    #[error("prekey expired")]
    Expired,
    #[error("prekey already consumed")]
    Consumed,
}

struct QueueEntry {
    prekey: AsyncPrekey,
    consumed: bool,
}

/// Maintains a bounded FIFO queue of single-use asynchronous prekeys.
pub struct PrekeyQueue<K: Kem> {
    capacity: usize,
    ttl_secs: u64,
    entries: HashMap<Uuid, QueueEntry>,
    order: VecDeque<Uuid>,
    _marker: PhantomData<K>,
}

impl<K: Kem> PrekeyQueue<K> {
    /// Creates a queue with maximum capacity `capacity` and prekey TTL `ttl`.
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            capacity: capacity.max(1),
            ttl_secs: ttl.as_secs().max(1),
            entries: HashMap::new(),
            order: VecDeque::new(),
            _marker: PhantomData,
        }
    }

    /// Publishes a new prekey, enforcing capacity and TTL constraints.
    pub fn publish(&mut self, mut prekey: AsyncPrekey, now: u64) -> Result<(), PrekeyError> {
        if self.entries.len() >= self.capacity {
            return Err(PrekeyError::QueueFull);
        }
        if prekey.expires_at <= now {
            return Err(PrekeyError::Expired);
        }
        let max_expiry = now.saturating_add(self.ttl_secs);
        if prekey.expires_at > max_expiry {
            prekey.expires_at = max_expiry;
        }
        let id = prekey.id();
        self.entries.insert(
            id,
            QueueEntry {
                prekey,
                consumed: false,
            },
        );
        self.order.push_back(id);
        Ok(())
    }

    /// Fetches and consumes the next available prekey.
    pub fn consume_next(&mut self, now: u64) -> Result<AsyncPrekey, PrekeyError> {
        self.prune(now);
        while let Some(id) = self.order.pop_front() {
            if let Some(entry) = self.entries.get_mut(&id) {
                if entry.consumed {
                    continue;
                }
                entry.consumed = true;
                return Ok(entry.prekey.clone());
            }
        }
        Err(PrekeyError::UnknownPrekey)
    }

    /// Consumes a specific prekey by identifier.
    pub fn consume(&mut self, id: &Uuid, now: u64) -> Result<AsyncPrekey, PrekeyError> {
        self.prune(now);
        let entry = self.entries.get_mut(id).ok_or(PrekeyError::UnknownPrekey)?;
        if entry.consumed {
            return Err(PrekeyError::Consumed);
        }
        if entry.prekey.expires_at <= now {
            return Err(PrekeyError::Expired);
        }
        entry.consumed = true;
        Ok(entry.prekey.clone())
    }

    /// Expires stale prekeys from the queue.
    pub fn prune(&mut self, now: u64) {
        self.order.retain(|id| {
            if let Some(entry) = self.entries.get(id) {
                if entry.prekey.expires_at > now && !entry.consumed {
                    return true;
                }
            }
            self.entries.remove(id);
            false
        });
    }

    /// Returns the number of prekeys that are still available for use.
    pub fn available(&self, now: u64) -> usize {
        self.entries
            .values()
            .filter(|entry| !entry.consumed && entry.prekey.expires_at > now)
            .count()
    }
}

/// Rekey thresholds enforcing message and time based session lifetimes.
#[derive(Clone, Copy, Debug)]
pub struct SessionRekeyPolicy {
    max_messages: u64,
    max_duration: Duration,
}

impl SessionRekeyPolicy {
    /// Constructs a new policy limiting sessions to at most `max_messages` messages
    /// or `max_duration` wall-clock time.
    pub fn new(max_messages: u64, max_duration: Duration) -> Self {
        Self {
            max_messages: max_messages.max(1),
            max_duration,
        }
    }
}

/// Errors produced when tracking session lifecycle state.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SessionLifecycleError {
    #[error("session has been tombstoned due to skipped key overflow")]
    Tombstoned,
}

/// Tracks message counters, tombstones, and rekey deadlines for a Double Ratchet session.
pub struct SessionLifecycle {
    policy: SessionRekeyPolicy,
    established_at: Instant,
    message_count: u64,
    skipped_keys: usize,
    max_skipped: usize,
    tombstoned: bool,
}

impl SessionLifecycle {
    /// Creates a new session lifecycle tracker.
    pub fn new(policy: SessionRekeyPolicy, max_skipped: usize, now: Instant) -> Self {
        Self {
            policy,
            established_at: now,
            message_count: 0,
            skipped_keys: 0,
            max_skipped: max_skipped.max(1),
            tombstoned: false,
        }
    }

    /// Records that a ciphertext was processed, updating skip counters.
    pub fn record_message(&mut self, skipped: usize) -> Result<(), SessionLifecycleError> {
        if self.tombstoned {
            return Err(SessionLifecycleError::Tombstoned);
        }
        self.message_count = self.message_count.saturating_add(1);
        self.skipped_keys = self.skipped_keys.saturating_add(skipped);
        if self.skipped_keys > self.max_skipped {
            self.tombstoned = true;
            return Err(SessionLifecycleError::Tombstoned);
        }
        Ok(())
    }

    /// Indicates whether the session must perform a rekey based on policy limits.
    pub fn should_rekey(&self, now: Instant) -> bool {
        if self.tombstoned {
            return true;
        }
        if self.message_count >= self.policy.max_messages {
            return true;
        }
        now.duration_since(self.established_at) >= self.policy.max_duration
    }

    /// Marks the session as successfully rekeyed, resetting counters.
    pub fn mark_rekeyed(&mut self, now: Instant) {
        self.established_at = now;
        self.message_count = 0;
        self.skipped_keys = 0;
        self.tombstoned = false;
    }

    /// Returns whether the session is tombstoned.
    pub fn is_tombstoned(&self) -> bool {
        self.tombstoned
    }
}

/// Signed reachability challenge used for compromise detection pings.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReachabilityPing {
    device_id: Uuid,
    nonce: [u8; 32],
    issued_at: u64,
    signature: Vec<u8>,
}

/// Errors encountered while validating reachability pings.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PingError {
    #[error("ping issued in the future (now={now}, issued_at={issued_at})")]
    NotYetValid { now: u64, issued_at: u64 },
    #[error("ping expired (now={now}, issued_at={issued_at}, max_skew={max_skew})")]
    Expired {
        now: u64,
        issued_at: u64,
        max_skew: u64,
    },
    #[error("ping signed by unexpected device")]
    WrongDevice,
    #[error("invalid ping signature")]
    InvalidSignature,
}

impl ReachabilityPing {
    /// Creates and signs a reachability ping for the specified device.
    pub fn sign(device: &ed25519::Keypair, device_id: Uuid, issued_at: u64) -> Self {
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        let mut payload = Vec::new();
        payload.extend_from_slice(device_id.as_bytes());
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&issued_at.to_le_bytes());
        let signature = device.sign(&payload);
        Self {
            device_id,
            nonce,
            issued_at,
            signature,
        }
    }

    /// Verifies the ping using the device's long-term key and allowed clock skew.
    pub fn verify(
        &self,
        device_id: &Uuid,
        device_key: &ed25519::PublicKey,
        now: u64,
        max_skew: Duration,
    ) -> Result<(), PingError> {
        if &self.device_id != device_id {
            return Err(PingError::WrongDevice);
        }
        let max_skew_secs = max_skew.as_secs();
        if now + max_skew_secs < self.issued_at {
            return Err(PingError::NotYetValid {
                now,
                issued_at: self.issued_at,
            });
        }
        if now.saturating_sub(self.issued_at) > max_skew_secs {
            return Err(PingError::Expired {
                now,
                issued_at: self.issued_at,
                max_skew: max_skew_secs,
            });
        }
        let mut payload = Vec::new();
        payload.extend_from_slice(self.device_id.as_bytes());
        payload.extend_from_slice(&self.nonce);
        payload.extend_from_slice(&self.issued_at.to_le_bytes());
        if device_key.verify(&payload, &self.signature) {
            Ok(())
        } else {
            Err(PingError::InvalidSignature)
        }
    }
}

/// Encrypted recovery share published into the VKD for threshold recovery.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryShare<K: Kem> {
    recipient: Vec<u8>,
    epoch: u64,
    kem_ciphertext: Vec<u8>,
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
    aad: Vec<u8>,
    #[serde(skip)]
    _marker: PhantomData<K>,
}

impl<K: Kem> RecoveryShare<K> {
    /// Returns the identifier of the intended recipient.
    pub fn recipient(&self) -> &[u8] {
        &self.recipient
    }

    /// Returns the epoch where the share was published.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns the associated additional authenticated data.
    pub fn aad(&self) -> &[u8] {
        &self.aad
    }

    fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    fn nonce(&self) -> &[u8; 12] {
        &self.nonce
    }

    fn kem_ciphertext(&self) -> &[u8] {
        &self.kem_ciphertext
    }
}

/// Errors occurring during social recovery share encryption/decryption.
#[derive(Debug, Error)]
pub enum RecoveryError {
    #[error("cryptographic error: {0:?}")]
    Crypto(CryptoError),
    #[error("aead error")]
    Aead,
    #[error("hkdf expansion failed")]
    Hkdf,
}

impl From<CryptoError> for RecoveryError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

fn derive_recovery_key(secret: &SharedSecret) -> Result<[u8; 32], RecoveryError> {
    let hk = Hkdf::<Sha256>::new(None, secret.as_ref());
    let mut key = [0u8; 32];
    hk.expand(b"VKD-RECOVERY-KEY", &mut key)
        .map_err(|_| RecoveryError::Hkdf)?;
    Ok(key)
}

/// Encrypts a recovery share to a recipient's post-quantum public key.
pub fn encrypt_recovery_share<K: Kem>(
    secret: &[u8],
    recipient_id: Vec<u8>,
    recipient_pk: &K::PublicKey,
    epoch: u64,
    aad: &[u8],
) -> Result<RecoveryShare<K>, RecoveryError> {
    let (kem_ct, shared) = K::encapsulate(recipient_pk)?;
    let key = derive_recovery_key(&shared)?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| RecoveryError::Aead)?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: secret, aad })
        .map_err(|_| RecoveryError::Aead)?;
    Ok(RecoveryShare {
        recipient: recipient_id,
        epoch,
        kem_ciphertext: K::serialize_ct(&kem_ct),
        nonce,
        ciphertext,
        aad: aad.to_vec(),
        _marker: PhantomData,
    })
}

/// Decrypts a recovery share using the owner's recovery private key share.
pub fn decrypt_recovery_share<K: Kem>(
    share: &RecoveryShare<K>,
    secret_key: &K::SecretKey,
) -> Result<Zeroizing<Vec<u8>>, RecoveryError> {
    let kem_ct = K::deserialize_ct(share.kem_ciphertext())?;
    let shared = K::decapsulate(&kem_ct, secret_key)?;
    let key = derive_recovery_key(&shared)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| RecoveryError::Aead)?;
    let nonce = *share.nonce();
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: share.ciphertext(),
                aad: share.aad(),
            },
        )
        .map_err(|_| RecoveryError::Aead)?;
    Ok(Zeroizing::from(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MlKem1024;

    fn audit_hash(tag: u8) -> [u8; 32] {
        [tag; 32]
    }

    fn sign_operation(
        signer: &MasterSigningKey,
        epoch: u64,
        prev: [u8; 32],
        next: [u8; 32],
        operation: AuditOperation,
    ) -> AuditProof {
        let body = AuditBody::new(epoch, prev, next, operation, None);
        signer.sign_audit(body).unwrap()
    }

    #[test]
    fn registry_validates_and_revokes_certificates() {
        let master = ed25519::Keypair::generate();
        let signing = MasterSigningKey::new(master.clone());
        let identity = signing.identity();
        let mut registry = DeviceRegistry::new(identity.clone(), Duration::from_secs(86_400));
        let device_id = Uuid::new_v4();
        let now = 1_000u64;
        let body = DeviceCertificateBody::new(
            device_id,
            now - 10,
            now + 3_600,
            vec![1u8; 32],
            [2u8; 32],
            None,
        );
        let cert = signing.sign(body).unwrap();
        let fingerprint = cert.fingerprint().unwrap();
        let add_audit = sign_operation(
            &signing,
            1,
            ZERO_HASH,
            audit_hash(1),
            AuditOperation::DeviceAdd {
                device_id,
                cert_fingerprint: fingerprint,
            },
        );
        registry.register(cert, add_audit, now).unwrap();
        assert!(registry.is_trusted(&device_id, now).is_ok());
        let revoke_audit = sign_operation(
            &signing,
            2,
            audit_hash(1),
            audit_hash(2),
            AuditOperation::DeviceRevoke {
                device_ids: vec![device_id],
                reason: RevocationReason::CompromiseDetected,
            },
        );
        registry.revoke_devices(revoke_audit).unwrap();
        assert!(matches!(
            registry.is_trusted(&device_id, now),
            Err(DeviceRegistryError::Revoked { .. })
        ));
        assert_eq!(registry.revocation(&device_id).unwrap().epoch(), 2);
    }

    #[test]
    fn audit_chain_rejects_inconsistent_prev_hash() {
        let master = ed25519::Keypair::generate();
        let signing = MasterSigningKey::new(master.clone());
        let mut registry = DeviceRegistry::new(signing.identity(), Duration::from_secs(86_400));
        let now = 2_000u64;
        let first_device = Uuid::new_v4();
        let first_body = DeviceCertificateBody::new(
            first_device,
            now - 10,
            now + 3_600,
            vec![3u8; 32],
            [4u8; 32],
            None,
        );
        let first_cert = signing.sign(first_body).unwrap();
        let first_fingerprint = first_cert.fingerprint().unwrap();
        let add_audit = sign_operation(
            &signing,
            1,
            ZERO_HASH,
            audit_hash(1),
            AuditOperation::DeviceAdd {
                device_id: first_device,
                cert_fingerprint: first_fingerprint,
            },
        );
        registry
            .register(first_cert, add_audit, now)
            .expect("initial registration should succeed");

        let second_device = Uuid::new_v4();
        let second_body = DeviceCertificateBody::new(
            second_device,
            now - 5,
            now + 3_600,
            vec![5u8; 32],
            [6u8; 32],
            None,
        );
        let second_cert = signing.sign(second_body).unwrap();
        let second_fingerprint = second_cert.fingerprint().unwrap();
        let bad_audit = sign_operation(
            &signing,
            2,
            audit_hash(9),
            audit_hash(2),
            AuditOperation::DeviceAdd {
                device_id: second_device,
                cert_fingerprint: second_fingerprint,
            },
        );
        assert!(matches!(
            registry.register(second_cert, bad_audit, now),
            Err(DeviceRegistryError::Audit(
                AuditError::PrevHashMismatch { .. }
            ))
        ));
    }

    #[test]
    fn master_rotation_replaces_identity_and_clears_certs() {
        let old_master = ed25519::Keypair::generate();
        let new_master = ed25519::Keypair::generate();
        let old_signing = MasterSigningKey::new(old_master.clone());
        let mut registry = DeviceRegistry::new(old_signing.identity(), Duration::from_secs(86_400));
        let now = 3_000u64;
        let device_id = Uuid::new_v4();
        let body = DeviceCertificateBody::new(
            device_id,
            now - 20,
            now + 3_600,
            vec![7u8; 32],
            [8u8; 32],
            None,
        );
        let cert = old_signing.sign(body).unwrap();
        let fingerprint = cert.fingerprint().unwrap();
        let add_audit = sign_operation(
            &old_signing,
            1,
            ZERO_HASH,
            audit_hash(1),
            AuditOperation::DeviceAdd {
                device_id,
                cert_fingerprint: fingerprint,
            },
        );
        registry
            .register(cert, add_audit, now)
            .expect("initial registration");
        assert_eq!(registry.active_count(), 1);

        let rotation_audit = sign_operation(
            &old_signing,
            2,
            audit_hash(1),
            audit_hash(2),
            AuditOperation::MasterRotate {
                new_master_key: new_master.public().to_bytes(),
            },
        );
        registry.rotate_master(rotation_audit).unwrap();
        assert_eq!(registry.active_count(), 0);
        assert_eq!(
            registry.master_identity().public_key().to_bytes(),
            new_master.public().to_bytes()
        );

        let new_signing = MasterSigningKey::new(new_master.clone());
        let new_device = Uuid::new_v4();
        let new_body = DeviceCertificateBody::new(
            new_device,
            now - 5,
            now + 3_600,
            vec![9u8; 32],
            [10u8; 32],
            None,
        );
        let new_cert = new_signing.sign(new_body).unwrap();
        let new_fingerprint = new_cert.fingerprint().unwrap();
        let post_rotation_audit = sign_operation(
            &new_signing,
            3,
            audit_hash(2),
            audit_hash(3),
            AuditOperation::DeviceAdd {
                device_id: new_device,
                cert_fingerprint: new_fingerprint,
            },
        );
        registry
            .register(new_cert, post_rotation_audit, now)
            .unwrap();
        assert!(registry.is_trusted(&new_device, now).is_ok());
    }

    #[test]
    fn registry_rejects_expired_certificates() {
        let master = ed25519::Keypair::generate();
        let signing = MasterSigningKey::new(master.clone());
        let identity = signing.identity();
        let mut registry = DeviceRegistry::new(identity, Duration::from_secs(3600));
        let device_id = Uuid::new_v4();
        let now = 5_000u64;
        let body = DeviceCertificateBody::new(
            device_id,
            now - 1_000,
            now - 100,
            vec![1u8; 32],
            [0u8; 32],
            None,
        );
        let cert = signing.sign(body).unwrap();
        let fingerprint = cert.fingerprint().unwrap();
        let audit = sign_operation(
            &signing,
            1,
            ZERO_HASH,
            audit_hash(1),
            AuditOperation::DeviceAdd {
                device_id,
                cert_fingerprint: fingerprint,
            },
        );
        assert!(matches!(
            registry.register(cert, audit, now),
            Err(DeviceRegistryError::Expired { .. })
        ));
    }

    #[test]
    fn attestation_must_be_fresh() {
        let master = ed25519::Keypair::generate();
        let signing = MasterSigningKey::new(master.clone());
        let identity = signing.identity();
        let mut registry = DeviceRegistry::new(identity, Duration::from_secs(3600));
        let device_id = Uuid::new_v4();
        let now = 10_000u64;
        let attestation = Attestation::new(AttestationKind::Tpm, vec![1, 2, 3], now - 1);
        let body = DeviceCertificateBody::new(
            device_id,
            now - 10,
            now + 100,
            vec![1u8; 32],
            [0u8; 32],
            Some(attestation),
        );
        let cert = signing.sign(body).unwrap();
        let fingerprint = cert.fingerprint().unwrap();
        let audit = sign_operation(
            &signing,
            1,
            ZERO_HASH,
            audit_hash(1),
            AuditOperation::DeviceAdd {
                device_id,
                cert_fingerprint: fingerprint,
            },
        );
        assert!(matches!(
            registry.register(cert, audit, now),
            Err(DeviceRegistryError::StaleAttestation { .. })
        ));
    }

    #[test]
    fn prekey_queue_enforces_single_use() {
        let mut queue: PrekeyQueue<MlKem1024> = PrekeyQueue::new(2, Duration::from_secs(3_600));
        let now = 1_000u64;
        let prekey = AsyncPrekey::new(Uuid::new_v4(), vec![1u8; 32], [2u8; 32], now + 1_000);
        queue.publish(prekey.clone(), now).unwrap();
        assert_eq!(queue.available(now), 1);
        let consumed = queue.consume(&prekey.id(), now).unwrap();
        assert_eq!(consumed.id(), prekey.id());
        assert!(matches!(
            queue.consume(&prekey.id(), now),
            Err(PrekeyError::UnknownPrekey)
        ));
    }

    #[test]
    fn session_lifecycle_triggers_rekey() {
        let policy = SessionRekeyPolicy::new(5, Duration::from_secs(60));
        let now = Instant::now();
        let mut lifecycle = SessionLifecycle::new(policy, 4, now);
        for _ in 0..5 {
            lifecycle.record_message(0).unwrap();
        }
        assert!(lifecycle.should_rekey(Instant::now()));
        lifecycle.mark_rekeyed(Instant::now());
        assert!(!lifecycle.should_rekey(Instant::now()));
    }

    #[test]
    fn session_tombstones_on_skip_overflow() {
        let policy = SessionRekeyPolicy::new(100, Duration::from_secs(600));
        let now = Instant::now();
        let mut lifecycle = SessionLifecycle::new(policy, 4, now);
        assert!(matches!(
            lifecycle.record_message(5),
            Err(SessionLifecycleError::Tombstoned)
        ));
        assert!(lifecycle.is_tombstoned());
    }

    #[test]
    fn reachability_ping_roundtrip() {
        let device = ed25519::Keypair::generate();
        let device_id = Uuid::new_v4();
        let now = 42_000u64;
        let ping = ReachabilityPing::sign(&device, device_id, now);
        ping.verify(&device_id, &device.public(), now, Duration::from_secs(60))
            .unwrap();
    }

    #[test]
    fn recovery_share_encrypt_decrypt() {
        let (pk, sk) = MlKem1024::keypair().unwrap();
        let secret = b"master seed".to_vec();
        let share =
            encrypt_recovery_share::<MlKem1024>(&secret, b"friend1".to_vec(), &pk, 7, b"aad")
                .unwrap();
        let decrypted = decrypt_recovery_share::<MlKem1024>(&share, &sk).unwrap();
        assert_eq!(decrypted.as_slice(), secret.as_slice());
    }
}
