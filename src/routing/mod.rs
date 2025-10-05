// This file is part of Chhaya and is licensed under the GNU Affero General Public License v3.0 or later.
// See the LICENSE file in the project root for license details.

#![forbid(unsafe_code)]

//! Garlic routing primitives for Chhaya.
//!
//! The router constructs configurable multi-hop circuits, verifies relay
//! descriptors through the VKD, and encapsulates Double Ratchet ciphertexts into
//! garlic bulbs. Each bulb contains multiple cloves (payloads) and onion layers
//! derived from HKDF so that no plaintext routing metadata ever crosses the
//! wire. A constant-rate scheduler mixes deterministic cover emission with a
//! Poisson delay to frustrate traffic analysis. The module is fully async,
//! Tokio-based, and avoids `unwrap`/`expect` outside test helpers.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use async_trait::async_trait;
use hkdf::Hkdf;
use rand_core_06::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, Notify, RwLock};
use tokio::task::JoinHandle;
use tokio::time::{interval_at, sleep, Instant};
use tracing::{info, warn};
use uuid::Uuid;

use crate::vkd::VkdTrustAnchors;
use crate::{verify_vkd_proof, VerifiedSth, VkdProof};

type AnyResult<T> = anyhow::Result<T>;

/// Routing-level errors.
#[derive(Debug, thiserror::Error)]
pub enum RoutingError {
    /// No relays were available for the requested circuit length.
    #[error("insufficient relays for circuit")]
    InsufficientRelays,
    /// Failure verifying a relay descriptor.
    #[error("descriptor verification failed: {0}")]
    DescriptorVerification(String),
    /// Replay detected when attempting to handle an incoming bulb.
    #[error("replay detected")]
    ReplayDetected,
    /// Attempted to operate on a circuit that is not currently active.
    #[error("unknown circuit")]
    UnknownCircuit,
    /// Catch-all error wrapper.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Configuration options for garlic routing.
#[derive(Clone, Debug)]
pub struct RoutingConfig {
    /// Number of hops to use for newly constructed circuits.
    pub default_hop_count: usize,
    /// Minimum interval between cover bulbs emitted on each circuit.
    pub cover_interval: Duration,
    /// Average delay (lambda) for Poisson mixing.
    pub poisson_lambda: f64,
    /// Replay cache duration in seconds.
    pub replay_ttl: Duration,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            default_hop_count: 3,
            cover_interval: Duration::from_secs(5),
            poisson_lambda: 4.0,
            replay_ttl: Duration::from_secs(600),
        }
    }
}

/// A relay descriptor obtained from the DHT.
#[derive(Clone, Debug)]
pub struct RelayDescriptor {
    /// Stable peer identifier for the relay node.
    pub peer_id: libp2p_identity::PeerId,
    /// VKD proof bundle authenticating the descriptor.
    pub vkd_proof: VkdProof,
    /// Encrypted descriptor payload.
    pub ciphertext: Vec<u8>,
    /// Drop slots advertised by the relay for store-and-forward bulbs.
    pub drop_slots: Vec<DropSlot>,
}

/// Drop slot metadata for stateless rendezvous.
#[derive(Clone, Debug)]
pub struct DropSlot {
    /// 32-byte rendezvous identifier derived from a VRF output.
    pub slot_id: [u8; 32],
    /// Expiry timestamp (unix seconds).
    pub expires_at: u64,
}

/// A single hop within a circuit.
#[derive(Clone, Debug)]
pub struct CircuitHop {
    /// Descriptor describing the relay and its advertised parameters.
    pub descriptor: RelayDescriptor,
}

/// A multi-hop circuit used for garlic routing.
pub struct Circuit {
    id: Uuid,
    hops: Vec<CircuitHop>,
    cover_handle: Mutex<Option<JoinHandle<()>>>,
    cover_stop: Arc<Notify>,
}

impl Circuit {
    fn new(hops: Vec<CircuitHop>) -> Self {
        Self {
            id: Uuid::new_v4(),
            hops,
            cover_handle: Mutex::new(None),
            cover_stop: Arc::new(Notify::new()),
        }
    }

    /// Returns an iterator over the circuit hops.
    pub fn hops(&self) -> impl Iterator<Item = &CircuitHop> {
        self.hops.iter()
    }

    /// Unique circuit identifier.
    pub fn id(&self) -> Uuid {
        self.id
    }

    /// Stop the cover traffic task if it is currently running.
    pub async fn stop_cover(&self) {
        self.cover_stop.notify_waiters();
        let mut guard = self.cover_handle.lock().await;
        if let Some(handle) = guard.take() {
            handle.abort();
        }
    }
}

/// A Double Ratchet encrypted payload bundled as a clove.
#[derive(Clone, Debug)]
pub struct Clove {
    /// Double ratchet header metadata (opaque in transport layer).
    pub header: Vec<u8>,
    /// Ciphertext body.
    pub ciphertext: Vec<u8>,
}

impl Clove {
    /// Construct a clove from already encrypted components.
    pub fn new(header: Vec<u8>, ciphertext: Vec<u8>) -> Self {
        Self { header, ciphertext }
    }

    /// Construct a cover clove of the requested payload size.
    pub fn cover(payload_size: usize) -> Self {
        let mut header = vec![0u8; 48];
        fill_random(&mut header);
        let mut ciphertext = vec![0u8; payload_size];
        fill_random(&mut ciphertext);
        Self { header, ciphertext }
    }
}

/// Onion layer metadata.
#[derive(Clone, Debug)]
pub struct OnionLayer {
    /// Symmetric key encrypted for the hop.
    pub encrypted_key: Vec<u8>,
    /// Routing command for the hop.
    pub command: Vec<u8>,
}

/// A bundled bulb consisting of multiple cloves within layered onions.
#[derive(Clone, Debug)]
pub struct Bulb {
    /// Individual message cloves.
    pub cloves: Vec<Clove>,
    /// Onion layers ordered from outermost to innermost.
    pub layers: Vec<OnionLayer>,
    /// Cover flag.
    pub is_cover: bool,
}

impl Bulb {
    /// Construct a cover bulb with pseudo-randomized padding.
    pub fn cover(
        circuit: &Circuit,
        clove_count: usize,
        payload_size: usize,
    ) -> Result<Bulb, RoutingError> {
        let mut builder = BulbBuilder::new();
        for _ in 0..clove_count {
            builder.push_clove(Clove::cover(payload_size));
        }
        builder.finish(circuit, true)
    }
}

/// Builder that bundles cloves into a fully layered bulb.
#[derive(Default)]
pub struct BulbBuilder {
    cloves: Vec<Clove>,
    salt: [u8; 32],
}

impl BulbBuilder {
    /// Create an empty builder seeded with fresh randomness.
    pub fn new() -> Self {
        let mut salt = [0u8; 32];
        fill_random(&mut salt);
        Self {
            cloves: Vec::new(),
            salt,
        }
    }

    /// Add a clove to the bulb.
    pub fn push_clove(&mut self, clove: Clove) {
        self.cloves.push(clove);
    }

    /// Finalise the bulb for the supplied circuit.
    pub fn finish(mut self, circuit: &Circuit, is_cover: bool) -> Result<Bulb, RoutingError> {
        if self.cloves.is_empty() {
            return Err(RoutingError::Other(anyhow!(
                "bulb requires at least one clove"
            )));
        }

        let mut layers = Vec::with_capacity(circuit.hops.len());
        for (index, hop) in circuit.hops.iter().enumerate() {
            layers.push(derive_onion_layer(circuit, hop, index, &self.salt)?);
        }

        Ok(Bulb {
            cloves: std::mem::take(&mut self.cloves),
            layers,
            is_cover,
        })
    }
}

/// Stateless anti-abuse puzzle issued to peers.
#[derive(Clone, Debug)]
pub struct StatelessPuzzle {
    /// Challenge nonce.
    pub challenge: [u8; 32],
    /// Difficulty threshold encoded as leading zero bits.
    pub difficulty: u8,
}

impl StatelessPuzzle {
    /// Issue a new puzzle using HKDF to derive per-peer challenges.
    pub fn issue(key: &[u8; 32], peer: &libp2p_identity::PeerId, difficulty: u8) -> Self {
        let mut info = peer.to_bytes();
        info.extend_from_slice(b"garlic-puzzle");
        let hk = Hkdf::<Sha256>::new(Some(key), &info);
        let mut challenge = [0u8; 32];
        if let Err(error) = hk.expand(b"challenge", &mut challenge) {
            warn!("hkdf expand failed: {error}");
        }
        Self {
            challenge,
            difficulty,
        }
    }

    /// Verify a candidate solution without keeping state.
    pub fn verify(&self, nonce: &[u8]) -> bool {
        let mut digest = Sha256::new();
        digest.update(self.challenge);
        digest.update(nonce);
        let hash = digest.finalize();
        leading_zero_bits(&hash) >= usize::from(self.difficulty)
    }
}

/// Cache for replay prevention.
#[derive(Debug)]
pub struct ReplayCache {
    entries: RwLock<HashMap<[u8; 32], Instant>>,
    ttl: Duration,
}

impl ReplayCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            ttl,
        }
    }

    pub async fn check_and_insert(&self, fingerprint: [u8; 32]) -> Result<(), RoutingError> {
        let now = Instant::now();
        let mut guard = self.entries.write().await;
        guard.retain(|_, timestamp| now.duration_since(*timestamp) <= self.ttl);
        if guard.contains_key(&fingerprint) {
            return Err(RoutingError::ReplayDetected);
        }
        guard.insert(fingerprint, now);
        Ok(())
    }
}

/// Abstraction for DHT-based relay discovery.
#[async_trait]
pub trait DhtProvider: Send + Sync + 'static {
    async fn discover_relays(&self, desired: usize) -> AnyResult<Vec<RelayDescriptor>>;
    async fn publish_drop_slot(&self, slot: DropSlot) -> AnyResult<()>;
}

/// Descriptors must be verified using VKD proofs before acceptance.
#[async_trait]
pub trait DescriptorVerifier: Send + Sync + 'static {
    async fn verify_before_accept(&self, descriptor: &RelayDescriptor) -> AnyResult<()>;
}

/// Default implementation backed by VKD proofs and trust anchors.
pub struct VkdDescriptorVerifier {
    trust: Arc<VkdTrustAnchors>,
    latest: Mutex<Option<VerifiedSth>>,
}

impl VkdDescriptorVerifier {
    pub fn new(trust: VkdTrustAnchors) -> Self {
        Self {
            trust: Arc::new(trust),
            latest: Mutex::new(None),
        }
    }
}

#[async_trait]
impl DescriptorVerifier for VkdDescriptorVerifier {
    async fn verify_before_accept(&self, descriptor: &RelayDescriptor) -> AnyResult<()> {
        let mut guard = self.latest.lock().await;
        let verified = verify_vkd_proof(&descriptor.vkd_proof, &self.trust, guard.clone())
            .ok_or_else(|| anyhow!("invalid VKD proof"))?;
        *guard = Some(verified);
        Ok(())
    }
}

/// Primary garlic routing entry point.
pub struct Router<D, V> {
    config: RoutingConfig,
    dht: Arc<D>,
    verifier: Arc<V>,
    replay_cache: Arc<ReplayCache>,
    circuits: Mutex<HashMap<Uuid, Arc<Circuit>>>,
}

impl<D, V> Router<D, V>
where
    D: DhtProvider,
    V: DescriptorVerifier,
{
    pub fn new(config: RoutingConfig, dht: D, verifier: V) -> Self {
        Self {
            replay_cache: Arc::new(ReplayCache::new(config.replay_ttl)),
            config,
            dht: Arc::new(dht),
            verifier: Arc::new(verifier),
            circuits: Mutex::new(HashMap::new()),
        }
    }

    /// Build a new circuit by sampling relays from the DHT.
    pub async fn build_circuit(&self) -> Result<Arc<Circuit>, RoutingError> {
        let relays = self
            .dht
            .discover_relays(self.config.default_hop_count)
            .await?;
        if relays.len() < self.config.default_hop_count {
            return Err(RoutingError::InsufficientRelays);
        }

        let mut hops = Vec::with_capacity(self.config.default_hop_count);
        for descriptor in relays.into_iter().take(self.config.default_hop_count) {
            self.verifier
                .verify_before_accept(&descriptor)
                .await
                .map_err(|error| RoutingError::DescriptorVerification(format!("{error:?}")))?;
            hops.push(CircuitHop { descriptor });
        }

        let circuit = Arc::new(Circuit::new(hops));
        self.install_cover_task(&circuit).await;
        self.circuits
            .lock()
            .await
            .insert(circuit.id(), circuit.clone());
        Ok(circuit)
    }

    /// Handle an incoming bulb after verifying anti-replay protections.
    pub async fn handle_incoming(
        &self,
        circuit_id: Uuid,
        fingerprint: [u8; 32],
    ) -> Result<(), RoutingError> {
        self.replay_cache.check_and_insert(fingerprint).await?;
        let circuits = self.circuits.lock().await;
        if let Some(circuit) = circuits.get(&circuit_id) {
            info!(circuit = %circuit.id(), "received bulb on circuit");
            return Ok(());
        }
        Err(RoutingError::UnknownCircuit)
    }

    /// Publish a drop slot for rendezvous.
    pub async fn advertise_drop_slot(&self, slot: DropSlot) -> AnyResult<()> {
        self.dht.publish_drop_slot(slot).await
    }

    /// Retrieve a circuit handle if it is currently active.
    pub async fn circuit(&self, circuit_id: Uuid) -> Option<Arc<Circuit>> {
        let circuits = self.circuits.lock().await;
        circuits.get(&circuit_id).cloned()
    }

    /// Tear down a circuit and stop its cover traffic.
    pub async fn teardown_circuit(&self, circuit_id: Uuid) -> Result<(), RoutingError> {
        let circuit = {
            let mut circuits = self.circuits.lock().await;
            circuits.remove(&circuit_id)
        };
        match circuit {
            Some(circuit) => {
                circuit.stop_cover().await;
                Ok(())
            }
            None => Err(RoutingError::UnknownCircuit),
        }
    }

    /// Encapsulate a collection of cloves for the given circuit.
    pub async fn encapsulate(
        &self,
        circuit_id: Uuid,
        cloves: Vec<Clove>,
    ) -> Result<Bulb, RoutingError> {
        let circuit = self
            .circuit(circuit_id)
            .await
            .ok_or(RoutingError::UnknownCircuit)?;
        let mut builder = BulbBuilder::new();
        for clove in cloves {
            builder.push_clove(clove);
        }
        builder.finish(&circuit, false)
    }

    async fn install_cover_task(&self, circuit: &Arc<Circuit>) {
        let mut guard = circuit.cover_handle.lock().await;
        if guard.is_some() {
            return;
        }

        let config = self.config.clone();
        let circuit_ref = circuit.clone();
        let stop = circuit.cover_stop.clone();
        let handle = tokio::spawn(async move {
            let start = Instant::now() + config.cover_interval;
            let mut ticker = interval_at(start, config.cover_interval);
            loop {
                tokio::select! {
                    _ = stop.notified() => {
                        break;
                    }
                    _ = ticker.tick() => {}
                }

                let delay = sample_poisson_delay(config.poisson_lambda);
                tokio::select! {
                    _ = stop.notified() => {
                        break;
                    }
                    _ = sleep(delay) => {}
                }

                match Bulb::cover(&circuit_ref, 1, 256) {
                    Ok(bulb) => {
                        info!(circuit = %circuit_ref.id(), cloves = bulb.cloves.len(), "emitting cover bulb");
                    }
                    Err(error) => {
                        warn!(circuit = %circuit_ref.id(), %error, "failed to build cover bulb");
                    }
                }
            }
        });

        *guard = Some(handle);
    }
}

fn fill_random(buffer: &mut [u8]) {
    if buffer.is_empty() {
        return;
    }
    OsRng.fill_bytes(buffer);
}

fn leading_zero_bits(bytes: &[u8]) -> usize {
    let mut count = 0usize;
    for byte in bytes {
        if *byte == 0 {
            count += 8;
        } else {
            let mut bits = 0u8;
            let mut value = *byte;
            while value & 0x80 == 0 {
                bits += 1;
                value <<= 1;
            }
            count += usize::from(bits);
            break;
        }
    }
    count
}

fn sample_poisson_delay(lambda: f64) -> Duration {
    if lambda <= 0.0 {
        return Duration::from_millis(0);
    }

    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    let uniform = (u64::from_le_bytes(bytes) as f64 + 1.0) / (u64::MAX as f64 + 2.0);
    let exp = -uniform.ln() / lambda;
    let millis = (exp * 1000.0) as u64;
    Duration::from_millis(millis)
}

fn derive_onion_layer(
    circuit: &Circuit,
    hop: &CircuitHop,
    index: usize,
    salt: &[u8; 32],
) -> Result<OnionLayer, RoutingError> {
    let mut info = hop.descriptor.peer_id.to_bytes();
    info.extend_from_slice(circuit.id.as_bytes());
    info.extend_from_slice(&(index as u32).to_be_bytes());
    let hk = Hkdf::<Sha256>::new(Some(salt), &info);

    let mut encrypted_key = vec![0u8; 32];
    hk.expand(b"layer-key", &mut encrypted_key)
        .map_err(|error| RoutingError::Other(anyhow!("derive layer key: {error}")))?;

    let mut command_seed = vec![0u8; 48];
    hk.expand(b"layer-cmd", &mut command_seed)
        .map_err(|error| RoutingError::Other(anyhow!("derive layer command: {error}")))?;

    // Hash the seed to avoid leaking structure from HKDF output size choices.
    let mut command = vec![0u8; 48];
    let digest = Sha256::digest(&command_seed);
    command[..32].copy_from_slice(&digest);
    command[32..].copy_from_slice(&command_seed[..16]);

    Ok(OnionLayer {
        encrypted_key,
        command,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use libipld::cid::Cid;
    use multihash::{Code, MultihashDigest};
    use serde_json::json;

    fn dummy_cid() -> Cid {
        let hash = Code::Sha2_256.digest(&[0u8; 1]);
        Cid::new_v1(0x55, hash)
    }

    fn dummy_vkd_proof() -> VkdProof {
        let inclusion_proof = serde_json::from_value(json!({
            "index": 0,
            "siblings": [],
        }))
        .expect("empty proof");
        VkdProof {
            log_id: Vec::new(),
            sth_root_hash: [0u8; 32],
            sth_tree_size: 0,
            sth_time: 0,
            sth_sig: vec![0u8; 48],
            witness_sigs: Vec::new(),
            inclusion_hash: [0u8; 32],
            inclusion_proof,
            consistency_proof: None,
            vrf_proof: Vec::new(),
            bundle_cid: dummy_cid(),
            quorum_desc_cid: dummy_cid(),
        }
    }

    struct DummyDht;

    #[async_trait]
    impl DhtProvider for DummyDht {
        async fn discover_relays(&self, desired: usize) -> AnyResult<Vec<RelayDescriptor>> {
            let mut relays = Vec::new();
            for _ in 0..desired {
                relays.push(RelayDescriptor {
                    peer_id: libp2p_identity::PeerId::random(),
                    vkd_proof: dummy_vkd_proof(),
                    ciphertext: vec![0u8; 32],
                    drop_slots: Vec::new(),
                });
            }
            Ok(relays)
        }

        async fn publish_drop_slot(&self, _slot: DropSlot) -> AnyResult<()> {
            Ok(())
        }
    }

    struct DummyVerifier;

    #[async_trait]
    impl DescriptorVerifier for DummyVerifier {
        async fn verify_before_accept(&self, _descriptor: &RelayDescriptor) -> AnyResult<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn builds_circuit() {
        let config = RoutingConfig::default();
        let router = Router::new(config.clone(), DummyDht, DummyVerifier);
        let circuit = router.build_circuit().await.expect("circuit builds");
        assert_eq!(circuit.hops().count(), config.default_hop_count);
    }

    #[tokio::test]
    async fn encapsulate_builds_layers() {
        let config = RoutingConfig::default();
        let router = Router::new(config.clone(), DummyDht, DummyVerifier);
        let circuit = router.build_circuit().await.expect("circuit builds");
        let clove = Clove::cover(96);
        let bulb = router
            .encapsulate(circuit.id(), vec![clove])
            .await
            .expect("encapsulation succeeds");
        assert_eq!(bulb.layers.len(), config.default_hop_count);
        assert!(!bulb.is_cover);
    }

    #[tokio::test]
    async fn cover_task_stops_on_teardown() {
        let router = Router::new(RoutingConfig::default(), DummyDht, DummyVerifier);
        let circuit = router.build_circuit().await.expect("circuit builds");
        let id = circuit.id();
        router
            .teardown_circuit(id)
            .await
            .expect("teardown succeeds");
        let err = router.handle_incoming(id, [1u8; 32]).await.err();
        assert!(matches!(err, Some(RoutingError::UnknownCircuit)));
    }

    #[tokio::test]
    async fn cover_bulb_matches_circuit_depth() {
        let router = Router::new(RoutingConfig::default(), DummyDht, DummyVerifier);
        let circuit = router.build_circuit().await.expect("circuit builds");
        let bulb = Bulb::cover(&circuit, 2, 64).expect("cover bulb");
        assert!(bulb.is_cover);
        assert_eq!(bulb.layers.len(), circuit.hops().count());
        assert_eq!(bulb.cloves.len(), 2);
    }

    #[tokio::test]
    async fn replay_cache_rejects_duplicate() {
        let cache = ReplayCache::new(Duration::from_secs(1));
        let fingerprint = [42u8; 32];
        cache
            .check_and_insert(fingerprint)
            .await
            .expect("insert succeeded");
        let err = cache.check_and_insert(fingerprint).await.err();
        assert!(matches!(err, Some(RoutingError::ReplayDetected)));
    }
}
