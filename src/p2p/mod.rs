#![forbid(unsafe_code)]

/// Bootstrap list verification and quorum helpers.
pub mod bootstrap;
mod exchange;
/// IPFS integration helpers for fetching VKD material.
pub mod ipfs;

use std::cmp::Ordering;
use std::collections::{hash_map::Entry, HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, Context, Result};
use blstrs::{G2Projective, Scalar};
use futures::{
    future::{BoxFuture, Either},
    stream::FuturesUnordered,
    StreamExt,
};
use group::Group;
use libp2p::{
    autonat,
    gossipsub::{
        self, score_parameter_decay, Event as GossipsubEvent, IdentTopic, MessageAcceptance,
        MessageAuthenticity, PeerScoreParams, PeerScoreThresholds, TopicScoreParams,
        ValidationMode,
    },
    identify,
    kad::{
        store::{MemoryStore, RecordStore},
        AddProviderOk, Behaviour as Kademlia, Event as KademliaEvent, GetProvidersOk,
        GetRecordError, GetRecordOk, PutRecordError, QueryId, QueryResult, Quorum, Record,
        RecordKey,
    },
    mdns,
    multiaddr::{Multiaddr, Protocol},
    noise, quic, relay,
    request_response::{self, InboundRequestId, OutboundRequestId, ProtocolSupport},
    swarm::{
        behaviour::toggle::Toggle, dial_opts::DialOpts, Config as SwarmConfig, NetworkBehaviour,
        Swarm, SwarmEvent,
    },
    tcp, websocket, yamux, PeerId, Transport,
};
use libp2p_mplex::Config as MplexConfig;
use thiserror::Error;
use tokio::{
    sync::{broadcast, mpsc, oneshot, RwLock},
    task::JoinHandle,
};
use tracing::{info, warn};

use crate::vkd::{verify_sth_announcement, SthAnnouncement, SthValidationError, VkdTrustAnchors};

/// Re-export the request/response exchange primitives for consumers.
pub use exchange::{
    ExchangeError, ExchangeEvent, ExchangeInboundError, ExchangeProtocol, ExchangeRequest,
    ExchangeResponse, InboundExchangeId, OutboundExchangeId,
};

/// Message delivered by the gossip subsystem along with metadata.
#[derive(Clone, Debug)]
pub struct GossipMessage {
    pub source: PeerId,
    pub topic: String,
    pub data: Vec<u8>,
}

/// Peer discovered through rendezvous with associated addresses.
#[derive(Clone, Debug)]
pub struct RendezvousPeer {
    pub peer_id: PeerId,
    pub addresses: Vec<Multiaddr>,
}

type RendezvousResponseTx = oneshot::Sender<Result<Vec<RendezvousPeer>>>;
type RendezvousFinish = (Option<RendezvousResponseTx>, Vec<RendezvousPeer>);

/// Configuration knobs used to construct a [`P2pNode`].
#[derive(Clone, Debug)]
pub struct P2pConfig {
    pub keypair: Option<libp2p::identity::Keypair>,
    pub listen_addresses: Vec<Multiaddr>,
    pub bootstrap_peers: Vec<(PeerId, Multiaddr)>,
    pub bootstrap_sources: Vec<bootstrap::BootstrapSource>,
    pub bootstrap_quorum: Option<bootstrap::TrustedBootstrapQuorum>,
    pub gossip_validation: ValidationMode,
    pub enable_mdns: bool,
    pub vkd_trust: Arc<VkdTrustAnchors>,
}

impl Default for P2pConfig {
    fn default() -> Self {
        let mut listen = Multiaddr::empty();
        listen.push(Protocol::Ip4(Ipv4Addr::UNSPECIFIED));
        listen.push(Protocol::Udp(0));
        listen.push(Protocol::QuicV1);
        let default_trust = VkdTrustAnchors::new(
            b"testlog".to_vec(),
            G2Projective::generator() * Scalar::from(42u64),
            vec![G2Projective::generator() * Scalar::from(43u64)],
            1,
            G2Projective::generator() * Scalar::from(42u64),
        )
        .expect("default VKD trust anchors");
        Self {
            keypair: None,
            listen_addresses: vec![listen],
            bootstrap_peers: Vec::new(),
            bootstrap_sources: Vec::new(),
            bootstrap_quorum: None,
            gossip_validation: ValidationMode::Strict,
            enable_mdns: true,
            vkd_trust: Arc::new(default_trust),
        }
    }
}

/// Running libp2p swarm and background tasks coordinating P2P messaging.
pub struct P2pNode {
    peer_id: PeerId,
    command_tx: mpsc::Sender<Command>,
    gossip_tx: broadcast::Sender<GossipMessage>,
    exchange_tx: broadcast::Sender<ExchangeEvent>,
    listen_addrs: Arc<RwLock<Vec<Multiaddr>>>,
    task: JoinHandle<Result<()>>,
}

const REPLICATION_TOPIC: &str = "p2p-replication";
const VKD_STH_TOPIC: &str = "/vkd/sth/v1";

const GOSSIP_MESH_N: usize = 8;
const GOSSIP_MESH_N_LOW: usize = 6;
const GOSSIP_MESH_N_HIGH: usize = 12;
const GOSSIP_MESH_OUTBOUND_MIN: usize = 3;
const GOSSIP_GOSSIP_THRESHOLD: f64 = -10.0;
const GOSSIP_PUBLISH_THRESHOLD: f64 = -20.0;
const GOSSIP_GRAYLIST_THRESHOLD: f64 = -40.0;
const GOSSIP_ACCEPT_PX_THRESHOLD: f64 = 5.0;
const GOSSIP_OPPORTUNISTIC_GRAFT_THRESHOLD: f64 = 3.0;

impl P2pNode {
    pub async fn run(mut config: P2pConfig) -> Result<Self> {
        let local_key = if let Some(key) = config.keypair.take() {
            key
        } else {
            libp2p::identity::Keypair::generate_ed25519()
        };
        let local_peer_id = PeerId::from(local_key.public());

        info!(%local_peer_id, "starting p2p node");

        let mut bootstrap = std::mem::take(&mut config.bootstrap_peers);
        let sources = std::mem::take(&mut config.bootstrap_sources);
        if !sources.is_empty() {
            let quorum = config
                .bootstrap_quorum
                .as_ref()
                .ok_or_else(|| anyhow!("bootstrap sources configured without quorum"))?;
            match bootstrap::collect_bootstrap_peers(&sources, quorum, SystemTime::now()).await {
                Ok(mut verified) => {
                    bootstrap.append(&mut verified);
                }
                Err(error) => {
                    warn!(target: "p2p", "bootstrap list verification failed: {error}");
                    return Err(error.into());
                }
            }
        }

        let enable_mdns = config.enable_mdns;
        if !enable_mdns {
            info!(target: "p2p", %local_peer_id, "mDNS discovery disabled by configuration");
        }

        let trust = Arc::clone(&config.vkd_trust);

        let mut swarm = build_swarm(&local_key, config.gossip_validation, enable_mdns)?;

        for addr in &config.listen_addresses {
            swarm
                .listen_on(addr.clone())
                .with_context(|| format!("failed to start listening on {addr}"))?;
        }

        let (command_tx, command_rx) = mpsc::channel(64);
        let (gossip_tx, _) = broadcast::channel(64);
        let (exchange_tx, _) = broadcast::channel(64);
        let listen_addrs = Arc::new(RwLock::new(Vec::new()));

        let task_listen_addrs = Arc::clone(&listen_addrs);
        let task_gossip = gossip_tx.clone();
        let task_exchange = exchange_tx.clone();

        let task_trust = Arc::clone(&trust);
        let task = tokio::spawn(async move {
            run_swarm(
                swarm,
                command_rx,
                task_listen_addrs,
                task_gossip,
                task_exchange,
                local_peer_id,
                bootstrap,
                task_trust,
            )
            .await
        });

        Ok(Self {
            peer_id: local_peer_id,
            command_tx,
            gossip_tx,
            exchange_tx,
            listen_addrs,
            task,
        })
    }

    pub async fn stop(self) -> Result<()> {
        info!(peer = %self.peer_id, "stopping p2p node");
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(Command::Shutdown { response: tx })
            .await
            .context("failed to send shutdown command")?;
        rx.await
            .context("failed to wait for shutdown acknowledgement")?;
        let task_result = self.task.await.context("p2p task join failure")?;
        task_result
    }

    #[must_use]
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub async fn listen_addrs(&self) -> Result<Vec<Multiaddr>> {
        let addrs = self.listen_addrs.read().await;
        Ok(addrs.clone())
    }

    pub async fn bootstrap(&self, peers: &[(PeerId, Multiaddr)]) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(Command::Bootstrap {
                peers: peers.to_vec(),
                response: tx,
            })
            .await
            .context("failed to send bootstrap command")?;
        rx.await.context("bootstrap task cancelled")?
    }

    pub async fn put_record(&self, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(Command::PutRecord {
                key,
                value,
                response: tx,
            })
            .await
            .context("failed to send put_record command")?;
        rx.await.context("put_record task cancelled")?
    }

    pub async fn get_record(&self, key: Vec<u8>) -> Result<Option<Vec<u8>>> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(Command::GetRecord { key, response: tx })
            .await
            .context("failed to send get_record command")?;
        rx.await.context("get_record task cancelled")?
    }

    pub async fn advertise_rendezvous(&self, did: &str) -> Result<()> {
        let key = rendezvous_record_key(did);
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(Command::ProvideRendezvous { key, response: tx })
            .await
            .context("failed to send rendezvous provide command")?;
        rx.await.context("rendezvous provide task cancelled")?
    }

    pub async fn discover_by_did(&self, did: &str) -> Result<Vec<RendezvousPeer>> {
        let key = rendezvous_record_key(did);
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(Command::FindRendezvousProviders { key, response: tx })
            .await
            .context("failed to send rendezvous lookup command")?;
        rx.await.context("rendezvous lookup task cancelled")?
    }

    pub async fn publish(&self, topic: &str, data: Vec<u8>) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(Command::Publish {
                topic: topic.to_owned(),
                data,
                response: tx,
            })
            .await
            .context("failed to send publish command")?;
        rx.await.context("publish task cancelled")?
    }

    pub async fn subscribe(&self, topic: &str) -> Result<broadcast::Receiver<GossipMessage>> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(Command::Subscribe {
                topic: topic.to_owned(),
                response: tx,
            })
            .await
            .context("failed to send subscribe command")?;
        rx.await.context("subscribe task cancelled")??;
        Ok(self.gossip_tx.subscribe())
    }

    #[must_use]
    pub fn exchange_events(&self) -> broadcast::Receiver<ExchangeEvent> {
        self.exchange_tx.subscribe()
    }

    pub async fn send_exchange_request(
        &self,
        peer: PeerId,
        request: ExchangeRequest,
    ) -> std::result::Result<ExchangeResponse, ExchangeError> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(Command::SendExchangeRequest {
                peer,
                request,
                response: tx,
            })
            .await
            .map_err(|_| ExchangeError::ChannelClosed)?;
        rx.await.map_err(|_| ExchangeError::ChannelClosed)?
    }

    pub async fn respond_exchange(
        &self,
        request_id: InboundRequestId,
        response: ExchangeResponse,
    ) -> std::result::Result<(), ExchangeError> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(Command::SendExchangeResponse {
                request_id,
                response,
                result: tx,
            })
            .await
            .map_err(|_| ExchangeError::ChannelClosed)?;
        rx.await.map_err(|_| ExchangeError::ChannelClosed)?
    }
}

fn rendezvous_record_key(did: &str) -> RecordKey {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"chhaya:did:rendezvous:");
    hasher.update(did.as_bytes());
    let digest = hasher.finalize();
    RecordKey::new(digest.as_bytes())
}

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "NodeEvent", prelude = "libp2p::swarm::derive_prelude")]
struct NodeBehaviour {
    kademlia: Kademlia<MemoryStore>,
    gossipsub: gossipsub::Behaviour,
    autonat: autonat::Behaviour,
    identify: identify::Behaviour,
    relay: relay::client::Behaviour,
    mdns: Toggle<mdns::tokio::Behaviour>,
    exchange: request_response::Behaviour<exchange::ExchangeCodec>,
}

enum NodeEvent {
    Kademlia(KademliaEvent),
    Gossipsub(GossipsubEvent),
    Autonat(autonat::Event),
    Identify(Box<identify::Event>),
    Relay(relay::client::Event),
    Mdns(mdns::Event),
    Exchange(Box<request_response::Event<ExchangeRequest, ExchangeResponse>>),
}

impl From<KademliaEvent> for NodeEvent {
    fn from(event: KademliaEvent) -> Self {
        Self::Kademlia(event)
    }
}

impl From<GossipsubEvent> for NodeEvent {
    fn from(event: GossipsubEvent) -> Self {
        Self::Gossipsub(event)
    }
}

impl From<autonat::Event> for NodeEvent {
    fn from(event: autonat::Event) -> Self {
        Self::Autonat(event)
    }
}

impl From<identify::Event> for NodeEvent {
    fn from(event: identify::Event) -> Self {
        Self::Identify(Box::new(event))
    }
}

impl From<relay::client::Event> for NodeEvent {
    fn from(event: relay::client::Event) -> Self {
        Self::Relay(event)
    }
}

impl From<mdns::Event> for NodeEvent {
    fn from(event: mdns::Event) -> Self {
        Self::Mdns(event)
    }
}

impl From<request_response::Event<ExchangeRequest, ExchangeResponse>> for NodeEvent {
    fn from(event: request_response::Event<ExchangeRequest, ExchangeResponse>) -> Self {
        Self::Exchange(Box::new(event))
    }
}

#[derive(Debug)]
enum Command {
    Bootstrap {
        peers: Vec<(PeerId, Multiaddr)>,
        response: oneshot::Sender<Result<()>>,
    },
    PutRecord {
        key: Vec<u8>,
        value: Vec<u8>,
        response: oneshot::Sender<Result<()>>,
    },
    GetRecord {
        key: Vec<u8>,
        response: oneshot::Sender<Result<Option<Vec<u8>>>>,
    },
    ProvideRendezvous {
        key: RecordKey,
        response: oneshot::Sender<Result<()>>,
    },
    FindRendezvousProviders {
        key: RecordKey,
        response: oneshot::Sender<Result<Vec<RendezvousPeer>>>,
    },
    Publish {
        topic: String,
        data: Vec<u8>,
        response: oneshot::Sender<Result<()>>,
    },
    Subscribe {
        topic: String,
        response: oneshot::Sender<Result<()>>,
    },
    SendExchangeRequest {
        peer: PeerId,
        request: ExchangeRequest,
        response: oneshot::Sender<std::result::Result<ExchangeResponse, ExchangeError>>,
    },
    SendExchangeResponse {
        request_id: InboundRequestId,
        response: ExchangeResponse,
        result: oneshot::Sender<std::result::Result<(), ExchangeError>>,
    },
    Shutdown {
        response: oneshot::Sender<()>,
    },
}

#[derive(Debug)]
struct ProviderQueryState {
    response: Option<oneshot::Sender<Result<Vec<RendezvousPeer>>>>,
    key: RecordKey,
    discovered: HashMap<PeerId, HashSet<Multiaddr>>,
    order: Vec<PeerId>,
    dialled_without_addr: HashSet<PeerId>,
}

impl ProviderQueryState {
    fn for_client(response: oneshot::Sender<Result<Vec<RendezvousPeer>>>, key: RecordKey) -> Self {
        Self {
            response: Some(response),
            key,
            discovered: HashMap::new(),
            order: Vec::new(),
            dialled_without_addr: HashSet::new(),
        }
    }

    fn without_response(key: RecordKey) -> Self {
        Self {
            response: None,
            key,
            discovered: HashMap::new(),
            order: Vec::new(),
            dialled_without_addr: HashSet::new(),
        }
    }

    fn key_bytes(&self) -> Vec<u8> {
        self.key.to_vec()
    }

    fn key_matches(&self, other: &[u8]) -> bool {
        self.key.as_ref() == other
    }

    fn note_providers<I>(
        &mut self,
        providers: I,
        provider_map: &HashMap<PeerId, Vec<Multiaddr>>,
    ) -> (HashMap<PeerId, Vec<Multiaddr>>, Vec<PeerId>)
    where
        I: IntoIterator<Item = PeerId>,
    {
        let mut dial_map: HashMap<PeerId, Vec<Multiaddr>> = HashMap::new();
        let mut peer_only = Vec::new();

        for peer in providers {
            if let Entry::Vacant(entry) = self.discovered.entry(peer) {
                entry.insert(HashSet::new());
                self.order.push(peer);
            }

            let entry = self
                .discovered
                .get_mut(&peer)
                .expect("provider entry initialised");

            if let Some(addresses) = provider_map.get(&peer) {
                let mut inserted = false;
                for addr in addresses {
                    if entry.insert(addr.clone()) {
                        inserted = true;
                        dial_map.entry(peer).or_default().push(addr.clone());
                    }
                }
                if !inserted && entry.is_empty() && self.dialled_without_addr.insert(peer) {
                    peer_only.push(peer);
                }
            } else if entry.is_empty() && self.dialled_without_addr.insert(peer) {
                peer_only.push(peer);
            }
        }

        (dial_map, peer_only)
    }

    fn finish(self) -> RendezvousFinish {
        let ProviderQueryState {
            response,
            key: _,
            mut discovered,
            order,
            ..
        } = self;

        let mut peers = Vec::with_capacity(order.len());
        for peer in order {
            let addresses_set = discovered.remove(&peer).unwrap_or_default();
            let mut addresses: Vec<_> = addresses_set.into_iter().collect();
            addresses.sort_by_key(|a| a.to_string());
            peers.push(RendezvousPeer {
                peer_id: peer,
                addresses,
            });
        }

        (response, peers)
    }

    fn absorb_store(&mut self, swarm: &mut Swarm<NodeBehaviour>) {
        let provider_records = {
            let behaviour = swarm.behaviour_mut();
            behaviour.kademlia.store_mut().providers(&self.key)
        };
        if provider_records.is_empty() {
            return;
        }
        let provider_map: HashMap<PeerId, Vec<Multiaddr>> = provider_records
            .into_iter()
            .map(|record| (record.provider, record.addresses))
            .collect();
        let provider_ids = provider_map.keys().copied().collect::<Vec<_>>();
        let _ = self.note_providers(provider_ids, &provider_map);
    }
}

const PROVIDER_RETRY_BASE_MS: u64 = 250;
const PROVIDER_RETRY_MAX_MS: u64 = 8_000;
const PROVIDER_RETRY_MAX_ATTEMPTS: u32 = 5;

#[derive(Debug, Default)]
struct ProviderBackoff {
    attempt: u32,
    pending: bool,
}

impl ProviderBackoff {
    fn schedule_with_backoff(&mut self) -> Option<Duration> {
        if self.pending {
            return None;
        }
        let exponent = self.attempt.min(PROVIDER_RETRY_MAX_ATTEMPTS);
        let multiplier = 1_u64 << exponent;
        let millis = (PROVIDER_RETRY_BASE_MS.saturating_mul(multiplier)).min(PROVIDER_RETRY_MAX_MS);
        self.attempt = self.attempt.saturating_add(1);
        self.pending = true;
        Some(Duration::from_millis(millis))
    }

    fn schedule_immediate(&mut self) -> Option<Duration> {
        if self.pending {
            return None;
        }
        self.attempt = 0;
        self.pending = true;
        Some(Duration::from_millis(0))
    }

    fn mark_triggered(&mut self) {
        self.pending = false;
    }

    fn reset(&mut self) {
        self.attempt = 0;
        self.pending = false;
    }
}

fn build_behaviour(
    keypair: &libp2p::identity::Keypair,
    relay_behaviour: relay::client::Behaviour,
    validation_mode: ValidationMode,
    enable_mdns: bool,
) -> Result<NodeBehaviour> {
    let peer_id = PeerId::from(keypair.public());
    let store = MemoryStore::new(peer_id);
    let kademlia = Kademlia::new(peer_id, store);

    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .validation_mode(validation_mode)
        .validate_messages()
        .mesh_n(GOSSIP_MESH_N)
        .mesh_n_low(GOSSIP_MESH_N_LOW)
        .mesh_n_high(GOSSIP_MESH_N_HIGH)
        .mesh_outbound_min(GOSSIP_MESH_OUTBOUND_MIN)
        .message_id_fn(|message: &gossipsub::Message| {
            gossipsub::MessageId::from(blake3::hash(&message.data).as_bytes().to_vec())
        })
        .build()
        .context("failed to build gossipsub config")?;
    let mut gossipsub = gossipsub::Behaviour::new(
        MessageAuthenticity::Signed(keypair.clone()),
        gossipsub_config,
    )
    .map_err(|err| anyhow!(err))?;

    let score_params = PeerScoreParams {
        topic_score_cap: 64.0,
        app_specific_weight: 0.0,
        decay_interval: Duration::from_secs(1),
        decay_to_zero: 0.01,
        retain_score: Duration::from_secs(600),
        behaviour_penalty_weight: -20.0,
        behaviour_penalty_threshold: 1.0,
        behaviour_penalty_decay: score_parameter_decay(Duration::from_secs(90)),
        ip_colocation_factor_weight: -15.0,
        ip_colocation_factor_threshold: 3.0,
        slow_peer_weight: -1.0,
        slow_peer_threshold: 1.0,
        slow_peer_decay: score_parameter_decay(Duration::from_secs(60)),
        ..PeerScoreParams::default()
    };

    let score_thresholds = PeerScoreThresholds {
        gossip_threshold: GOSSIP_GOSSIP_THRESHOLD,
        publish_threshold: GOSSIP_PUBLISH_THRESHOLD,
        graylist_threshold: GOSSIP_GRAYLIST_THRESHOLD,
        accept_px_threshold: GOSSIP_ACCEPT_PX_THRESHOLD,
        opportunistic_graft_threshold: GOSSIP_OPPORTUNISTIC_GRAFT_THRESHOLD,
    };

    gossipsub
        .with_peer_score(score_params, score_thresholds)
        .map_err(|err| anyhow!(err))?;

    let topic_params = TopicScoreParams {
        topic_weight: 1.0,
        time_in_mesh_cap: 300.0,
        first_message_deliveries_weight: 2.0,
        first_message_deliveries_decay: score_parameter_decay(Duration::from_secs(60)),
        first_message_deliveries_cap: 200.0,
        mesh_message_deliveries_weight: -3.0,
        mesh_message_deliveries_decay: score_parameter_decay(Duration::from_secs(60)),
        mesh_message_deliveries_cap: 20.0,
        mesh_message_deliveries_threshold: 10.0,
        mesh_message_deliveries_window: Duration::from_millis(200),
        mesh_message_deliveries_activation: Duration::from_secs(10),
        mesh_failure_penalty_weight: -5.0,
        mesh_failure_penalty_decay: score_parameter_decay(Duration::from_secs(120)),
        invalid_message_deliveries_weight: -100.0,
        invalid_message_deliveries_decay: score_parameter_decay(Duration::from_secs(600)),
        ..TopicScoreParams::default()
    };

    gossipsub
        .set_topic_params(IdentTopic::new(REPLICATION_TOPIC), topic_params.clone())
        .map_err(|err| anyhow!(err))?;
    gossipsub
        .set_topic_params(IdentTopic::new(VKD_STH_TOPIC), topic_params)
        .map_err(|err| anyhow!(err))?;

    let autonat = autonat::Behaviour::new(peer_id, Default::default());

    let identify_config = identify::Config::new("chhaya/0.1.0".into(), keypair.public());
    let identify = identify::Behaviour::new(identify_config);

    let mdns = if enable_mdns {
        Some(
            mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id)
                .context("failed to create mdns behaviour")?,
        )
    } else {
        None
    };

    let exchange_codec = exchange::ExchangeCodec;
    let exchange = request_response::Behaviour::with_codec(
        exchange_codec,
        [(exchange::ExchangeProtocol, ProtocolSupport::Full)],
        request_response::Config::default()
            .with_request_timeout(Duration::from_secs(60))
            .with_max_concurrent_streams(64),
    );

    Ok(NodeBehaviour {
        kademlia,
        gossipsub,
        autonat,
        identify,
        relay: relay_behaviour,
        mdns: Toggle::from(mdns),
        exchange,
    })
}

fn build_swarm(
    keypair: &libp2p::identity::Keypair,
    validation_mode: ValidationMode,
    enable_mdns: bool,
) -> Result<Swarm<NodeBehaviour>> {
    use libp2p::core::{muxing::StreamMuxerBox, transport::Boxed, upgrade};

    let peer_id = PeerId::from(keypair.public());

    let quic_transport = quic::tokio::Transport::new(quic::Config::new(keypair))
        .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)));

    let build_muxer = || upgrade::SelectUpgrade::new(yamux::Config::default(), MplexConfig::new());

    let tcp_transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true));
    let tcp_noise = noise::Config::new(keypair).context("failed to initialise tcp noise")?;
    let tcp_transport = tcp_transport
        .upgrade(upgrade::Version::V1Lazy)
        .authenticate(tcp_noise)
        .multiplex(build_muxer())
        .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)));

    let ws_transport = websocket::Config::new(tcp::tokio::Transport::new(
        tcp::Config::default().nodelay(true),
    ));
    let ws_noise = noise::Config::new(keypair).context("failed to initialise websocket noise")?;
    let ws_transport = ws_transport
        .upgrade(upgrade::Version::V1Lazy)
        .authenticate(ws_noise)
        .multiplex(build_muxer())
        .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)));

    let (relay_transport, relay_behaviour) = relay::client::new(peer_id);
    let relay_noise = noise::Config::new(keypair).context("failed to initialise relay noise")?;
    let relay_transport = relay_transport
        .upgrade(upgrade::Version::V1Lazy)
        .authenticate(relay_noise)
        .multiplex(build_muxer())
        .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)));

    let transport: Boxed<(PeerId, StreamMuxerBox)> = quic_transport
        .or_transport(tcp_transport)
        .map(|either, _| match either {
            Either::Left(output) => output,
            Either::Right(output) => output,
        })
        .or_transport(ws_transport)
        .map(|either, _| match either {
            Either::Left(output) => output,
            Either::Right(output) => output,
        })
        .or_transport(relay_transport)
        .map(|either, _| match either {
            Either::Left(output) => output,
            Either::Right(output) => output,
        })
        .boxed();

    let behaviour = build_behaviour(keypair, relay_behaviour, validation_mode, enable_mdns)?;

    let mut swarm = Swarm::new(
        transport,
        behaviour,
        peer_id,
        SwarmConfig::with_tokio_executor(),
    );
    swarm.behaviour_mut().kademlia.bootstrap().ok();
    Ok(swarm)
}

#[allow(clippy::too_many_arguments)]
async fn run_swarm(
    mut swarm: Swarm<NodeBehaviour>,
    mut command_rx: mpsc::Receiver<Command>,
    listen_addrs: Arc<RwLock<Vec<Multiaddr>>>,
    gossip_tx: broadcast::Sender<GossipMessage>,
    exchange_tx: broadcast::Sender<ExchangeEvent>,
    local_peer_id: PeerId,
    bootstrap: Vec<(PeerId, Multiaddr)>,
    trust: Arc<VkdTrustAnchors>,
) -> Result<()> {
    let mut pending_get: HashMap<QueryId, oneshot::Sender<Result<Option<Vec<u8>>>>> =
        HashMap::new();
    let mut pending_put: HashMap<QueryId, oneshot::Sender<Result<()>>> = HashMap::new();
    let mut pending_provide: HashMap<QueryId, oneshot::Sender<Result<()>>> = HashMap::new();
    let mut pending_provider_queries: HashMap<QueryId, ProviderQueryState> = HashMap::new();
    let mut pending_exchange: HashMap<
        OutboundRequestId,
        oneshot::Sender<std::result::Result<ExchangeResponse, ExchangeError>>,
    > = HashMap::new();
    let mut pending_responses: HashMap<
        InboundRequestId,
        request_response::ResponseChannel<ExchangeResponse>,
    > = HashMap::new();
    let mut provider_dials: HashMap<PeerId, HashSet<Vec<u8>>> = HashMap::new();
    let mut active_providers: HashMap<PeerId, HashSet<Vec<u8>>> = HashMap::new();
    let mut provider_backoff: HashMap<Vec<u8>, ProviderBackoff> = HashMap::new();
    let mut provider_retry: FuturesUnordered<BoxFuture<'static, Vec<u8>>> = FuturesUnordered::new();
    let mut tracked_provider_keys: HashSet<Vec<u8>> = HashSet::new();

    for (peer, addr) in bootstrap {
        swarm
            .behaviour_mut()
            .kademlia
            .add_address(&peer, addr.clone());
        if let Err(err) = swarm.dial(addr.clone()) {
            warn!(target: "p2p", %peer, address = %addr, "bootstrap dial failed: {err}");
        }
    }

    if let Err(error) = swarm.behaviour_mut().kademlia.bootstrap() {
        warn!(target: "p2p", "initial bootstrap query failed: {error}");
    }

    let replication_topic = IdentTopic::new(REPLICATION_TOPIC);
    if let Err(error) = swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&replication_topic)
    {
        warn!(target: "p2p", "failed to join replication mesh: {error}");
    }

    loop {
        tokio::select! {
            command = command_rx.recv() => {
                match command {
                    Some(Command::Bootstrap { peers, response }) => {
                        let mut result = Ok(());
                        for (peer, addr) in peers {
                            swarm.behaviour_mut().kademlia.add_address(&peer, addr.clone());
                            if let Err(err) = swarm.dial(addr.clone()) {
                                warn!(target: "p2p", %peer, address = %addr, "dial failed: {err}");
                                result = Err(anyhow!("failed to dial bootstrap peer"));
                            }
                        }
                        if let Err(error) = swarm.behaviour_mut().kademlia.bootstrap() {
                            warn!(target: "p2p", "bootstrap query failed: {error}");
                        }
                        let _ = response.send(result);
                    }
                    Some(Command::PutRecord { key, value, response }) => {
                        let record = Record {
                            key: RecordKey::new(&key),
                            value,
                            publisher: Some(local_peer_id),
                            expires: None,
                        };
                        let replication_payload = build_replication_payload(&key, &record.value);
                        let connected: Vec<_> = swarm.connected_peers().copied().collect();
                        let behaviour = swarm.behaviour_mut();
                        if let Err(error) = behaviour.kademlia.store_mut().put(record.clone()) {
                            warn!(target: "p2p", "failed to store record locally: {error}");
                        }
                        let mut peer_set: HashSet<PeerId> = connected.into_iter().collect();
                        for bucket in behaviour.kademlia.kbuckets() {
                            for entry in bucket.iter() {
                                peer_set.insert(*entry.node.key.preimage());
                            }
                        }
                        if !peer_set.is_empty() {
                            behaviour.kademlia.put_record_to(
                                record.clone(),
                                peer_set.into_iter(),
                                Quorum::One,
                            );
                        }
                        match behaviour.kademlia.put_record(record.clone(), Quorum::One) {
                            Ok(query_id) => {
                                pending_put.insert(query_id, response);
                            }
                            Err(err) => {
                                let _ = response.send(Err(anyhow!(err.to_string())));
                            }
                        }
                        if let Some(payload) = replication_payload {
                            if let Err(error) = behaviour
                                .gossipsub
                                .publish(IdentTopic::new(REPLICATION_TOPIC), payload)
                            {
                                warn!(target: "p2p", "replication publish failed: {error}");
                            }
                        }
                    }
                    Some(Command::GetRecord { key, response }) => {
                        let query_id = swarm
                            .behaviour_mut()
                            .kademlia
                            .get_record(RecordKey::new(&key));
                        pending_get.insert(query_id, response);
                    }
                    Some(Command::ProvideRendezvous { key, response }) => {
                        match swarm.behaviour_mut().kademlia.start_providing(key) {
                            Ok(query_id) => {
                                pending_provide.insert(query_id, response);
                            }
                            Err(error) => {
                                let _ = response.send(Err(anyhow!(error)));
                            }
                        }
                    }
                    Some(Command::FindRendezvousProviders { key, response }) => {
                        let key_bytes = key.to_vec();
                        if let Some(backoff) = provider_backoff.get_mut(&key_bytes) {
                            backoff.reset();
                        }
                        tracked_provider_keys.insert(key_bytes.clone());
                        let query_id = swarm
                            .behaviour_mut()
                            .kademlia
                            .get_providers(key.clone());
                        pending_provider_queries.insert(
                            query_id,
                            ProviderQueryState::for_client(response, key),
                        );
                    }
                    Some(Command::Publish { topic, data, response }) => {
                        let topic_hash = IdentTopic::new(topic.clone());
                        match swarm.behaviour_mut().gossipsub.publish(topic_hash, data) {
                            Ok(_) => {
                                let _ = response.send(Ok(()));
                            }
                            Err(err) => {
                                let _ = response.send(Err(anyhow!(err.to_string())));
                            }
                        }
                    }
                    Some(Command::Subscribe { topic, response }) => {
                        let topic_hash = IdentTopic::new(topic);
                        match swarm.behaviour_mut().gossipsub.subscribe(&topic_hash) {
                            Ok(_) => {
                                let _ = response.send(Ok(()));
                            }
                            Err(err) => {
                                let _ = response.send(Err(anyhow!(err.to_string())));
                            }
                        }
                    }
                    Some(Command::SendExchangeRequest {
                        peer,
                        request,
                        response,
                    }) => {
                        let request_id =
                            swarm.behaviour_mut().exchange.send_request(&peer, request);
                        pending_exchange.insert(request_id, response);
                    }
                    Some(Command::SendExchangeResponse {
                        request_id,
                        response,
                        result,
                    }) => {
                        if let Some(channel) = pending_responses.remove(&request_id) {
                            match swarm.behaviour_mut().exchange.send_response(channel, response) {
                                Ok(()) => {
                                    let _ = result.send(Ok(()));
                                }
                                Err(_) => {
                                    let _ = result.send(Err(ExchangeError::ResponseChannelClosed));
                                }
                            }
                        } else {
                            let _ = result.send(Err(ExchangeError::UnknownInbound(request_id)));
                        }
                    }
                    Some(Command::Shutdown { response }) => {
                        let _ = response.send(());
                        break;
                    }
                    None => break,
                }
            }
            Some(key_bytes) = provider_retry.next() => {
                if let Some(backoff) = provider_backoff.get_mut(&key_bytes) {
                    backoff.mark_triggered();
                }
                if pending_provider_queries
                    .values()
                    .any(|state| state.key_matches(&key_bytes))
                {
                    continue;
                }
                tracked_provider_keys.insert(key_bytes.clone());
                let record_key = RecordKey::new(&key_bytes);
                let query_id = swarm
                    .behaviour_mut()
                    .kademlia
                    .get_providers(record_key.clone());
                pending_provider_queries.insert(
                    query_id,
                    ProviderQueryState::without_response(record_key),
                );
            }
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        info!(target: "p2p", %address, "new listen address");
                        let mut addrs = listen_addrs.write().await;
                        if !addrs.iter().any(|existing| existing == &address) {
                            addrs.push(address);
                        }
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        if let Some(keys) = provider_dials.remove(&peer_id) {
                            if !gossipsub_peer_is_healthy(&swarm, &peer_id) {
                                let score = gossipsub_peer_score(&swarm, &peer_id);
                                warn!(
                                    target: "p2p",
                                    %peer_id,
                                    score = score,
                                    "disconnecting low-score provider"
                                );
                                for key in keys {
                                    tracked_provider_keys.insert(key.clone());
                                    schedule_provider_refresh(
                                        key,
                                        &mut provider_backoff,
                                        &mut provider_retry,
                                        true,
                                    );
                                }
                                if swarm.disconnect_peer_id(peer_id).is_err() {
                                    warn!(
                                        target: "p2p",
                                        %peer_id,
                                        "failed to disconnect low-score provider"
                                    );
                                }
                                continue;
                            }
                            let entry = active_providers.entry(peer_id).or_default();
                            for key in keys {
                                entry.insert(key.clone());
                                if let Some(backoff) = provider_backoff.get_mut(&key) {
                                    backoff.reset();
                                }
                            }
                        }
                    }
                    SwarmEvent::ConnectionClosed { peer_id, .. } => {
                        if let Some(keys) = active_providers.remove(&peer_id) {
                            for key in keys {
                                tracked_provider_keys.insert(key.clone());
                                schedule_provider_refresh(
                                    key,
                                    &mut provider_backoff,
                                    &mut provider_retry,
                                    false,
                                );
                            }
                        }
                    }
                    SwarmEvent::Behaviour(NodeEvent::Gossipsub(GossipsubEvent::Message { propagation_source, message_id, message })) => {
                        let topic = message.topic.to_string();
                        let (acceptance, deliver) = if topic == VKD_STH_TOPIC {
                            match validate_sth_gossip(&message.data, trust.as_ref()) {
                                Ok(_) => (MessageAcceptance::Accept, true),
                                Err(error) => {
                                    warn!(
                                        target: "p2p",
                                        %propagation_source,
                                        topic = %topic,
                                        "rejecting STH gossip: {error}"
                                    );
                                    (MessageAcceptance::Reject, false)
                                }
                            }
                        } else {
                            (MessageAcceptance::Accept, true)
                        };

                        let forwarded = swarm
                            .behaviour_mut()
                            .gossipsub
                            .report_message_validation_result(
                                &message_id,
                                &propagation_source,
                                acceptance,
                            );
                        if !forwarded {
                            warn!(
                                target: "p2p",
                                %propagation_source,
                                topic = %topic,
                                %message_id,
                                "gossip message missing from validation cache"
                            );
                        }

                        if !deliver {
                            continue;
                        }

                        if topic == REPLICATION_TOPIC {
                            if let Some((key, value)) = parse_replication_payload(&message.data) {
                                let record = Record {
                                    key: RecordKey::new(&key),
                                    value,
                                    publisher: Some(propagation_source),
                                    expires: None,
                                };
                                if let Err(error) = swarm.behaviour_mut().kademlia.store_mut().put(record.clone()) {
                                    warn!(target: "p2p", "failed to apply replicated record: {error}");
                                }
                                let _ = swarm
                                    .behaviour_mut()
                                    .kademlia
                                    .put_record(record, Quorum::One);
                            }
                            continue;
                        }

                        let gossip_message = GossipMessage {
                            source: propagation_source,
                            topic,
                            data: message.data.clone(),
                        };
                        let _ = gossip_tx.send(gossip_message);
                    }
                    SwarmEvent::Behaviour(NodeEvent::Kademlia(event)) => {
                        handle_kademlia_event(
                            event,
                            &mut swarm,
                            &mut pending_get,
                            &mut pending_put,
                            &mut pending_provide,
                            &mut pending_provider_queries,
                            &mut provider_dials,
                        );
                    }
                    SwarmEvent::Behaviour(NodeEvent::Mdns(event)) => match event {
                        mdns::Event::Discovered(list) => {
                            for (peer, addr) in list {
                                swarm.behaviour_mut().kademlia.add_address(&peer, addr.clone());
                                swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer);
                                if let Err(err) = swarm.dial(addr.clone()) {
                                    warn!(target: "p2p", %peer, address = %addr, "mdns dial failed: {err}");
                                }
                            }
                        }
                        mdns::Event::Expired(list) => {
                            for (peer, addr) in list {
                                swarm.behaviour_mut().kademlia.remove_address(&peer, &addr);
                                swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer);
                            }
                        }
                    },
                    SwarmEvent::Behaviour(NodeEvent::Exchange(event)) => {
                        let event = *event;
                        use request_response::Event as ReqResEvent;
                        use request_response::Message as ReqResMessage;

                        match event {
                            ReqResEvent::Message { peer, message, .. } => match message {
                                ReqResMessage::Request {
                                    request_id,
                                    request,
                                    channel,
                                } => {
                                    pending_responses.insert(request_id, channel);
                                    let event = ExchangeEvent::InboundRequest {
                                        peer,
                                        request_id,
                                        request,
                                    };
                                    if exchange_tx.send(event).is_err() {
                                        warn!(target: "p2p", %peer, %request_id, "dropping inbound exchange with no subscribers");
                                        pending_responses.remove(&request_id);
                                    }
                                }
                                ReqResMessage::Response {
                                    request_id,
                                    response,
                                } => {
                                    if let Some(tx) = pending_exchange.remove(&request_id) {
                                        let _ = tx.send(Ok(response));
                                    }
                                }
                            },
                            ReqResEvent::OutboundFailure {
                                peer,
                                request_id,
                                error,
                                ..
                            } => {
                                if let Some(tx) = pending_exchange.remove(&request_id) {
                                    let _ = tx.send(Err(error.into()));
                                } else {
                                    warn!(target: "p2p", %peer, %request_id, "outbound exchange failed: {error}");
                                }
                            }
                            ReqResEvent::InboundFailure {
                                peer,
                                request_id,
                                error,
                                ..
                            } => {
                                pending_responses.remove(&request_id);
                                let event = ExchangeEvent::InboundFailure {
                                    peer,
                                    request_id,
                                    error: error.into(),
                                };
                                let _ = exchange_tx.send(event);
                            }
                            ReqResEvent::ResponseSent { peer, request_id, .. } => {
                                pending_responses.remove(&request_id);
                                let event = ExchangeEvent::ResponseSent { peer, request_id };
                                let _ = exchange_tx.send(event);
                            }
                        }
                    }
                    SwarmEvent::Behaviour(NodeEvent::Autonat(event)) => {
                        match event {
                            autonat::Event::StatusChanged { old, new } => {
                                info!(target: "p2p", ?old, ?new, "autonat status changed");
                                if matches!(new, autonat::NatStatus::Private) {
                                    for key in tracked_provider_keys.iter().cloned() {
                                        schedule_provider_refresh(
                                            key,
                                            &mut provider_backoff,
                                            &mut provider_retry,
                                            true,
                                        );
                                    }
                                }
                            }
                            other => {
                                info!(target: "p2p", ?other, "autonat event");
                            }
                        }
                    }
                    SwarmEvent::Behaviour(NodeEvent::Identify(event)) => {
                        info!(target: "p2p", ?event, "identify event");
                    }
                    SwarmEvent::Behaviour(NodeEvent::Relay(event)) => {
                        info!(target: "p2p", ?event, "relay event");
                    }
                    SwarmEvent::OutgoingConnectionError { peer_id: Some(peer_id), error, .. } => {
                        warn!(target: "p2p", %peer_id, "outgoing connection error: {error}");
                        if let Some(keys) = provider_dials.remove(&peer_id) {
                            for key in keys {
                                tracked_provider_keys.insert(key.clone());
                                schedule_provider_refresh(
                                    key,
                                    &mut provider_backoff,
                                    &mut provider_retry,
                                    false,
                                );
                            }
                        }
                    }
                    SwarmEvent::OutgoingConnectionError { peer_id: None, error, .. } => {
                        warn!(target: "p2p", ?error, "outgoing connection error");
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(())
}

fn handle_kademlia_event(
    event: KademliaEvent,
    swarm: &mut Swarm<NodeBehaviour>,
    pending_get: &mut HashMap<QueryId, oneshot::Sender<Result<Option<Vec<u8>>>>>,
    pending_put: &mut HashMap<QueryId, oneshot::Sender<Result<()>>>,
    pending_provide: &mut HashMap<QueryId, oneshot::Sender<Result<()>>>,
    pending_provider_queries: &mut HashMap<QueryId, ProviderQueryState>,
    provider_dials: &mut HashMap<PeerId, HashSet<Vec<u8>>>,
) {
    if let KademliaEvent::OutboundQueryProgressed { id, result, .. } = event {
        match result {
            QueryResult::GetRecord(Ok(GetRecordOk::FoundRecord(record))) => {
                if let Some(tx) = pending_get.remove(&id) {
                    let value = record.record.value.clone();
                    let _ = tx.send(Ok(Some(value)));
                }
            }
            QueryResult::GetRecord(Ok(GetRecordOk::FinishedWithNoAdditionalRecord { .. }))
            | QueryResult::GetRecord(Err(GetRecordError::NotFound { .. })) => {
                if let Some(tx) = pending_get.remove(&id) {
                    let _ = tx.send(Ok(None));
                }
            }
            QueryResult::GetRecord(Err(err)) => {
                if let Some(tx) = pending_get.remove(&id) {
                    let _ = tx.send(Err(anyhow!(err.to_string())));
                }
            }
            QueryResult::PutRecord(Ok(_)) => {
                if let Some(tx) = pending_put.remove(&id) {
                    let _ = tx.send(Ok(()));
                }
            }
            QueryResult::PutRecord(Err(err)) => {
                if let Some(tx) = pending_put.remove(&id) {
                    match err {
                        PutRecordError::QuorumFailed { .. } => {
                            let _ = tx.send(Ok(()));
                        }
                        _ => {
                            let _ = tx.send(Err(anyhow!(err.to_string())));
                        }
                    }
                }
            }
            QueryResult::StartProviding(Ok(AddProviderOk { .. })) => {
                if let Some(tx) = pending_provide.remove(&id) {
                    let _ = tx.send(Ok(()));
                }
            }
            QueryResult::StartProviding(Err(err)) => {
                if let Some(tx) = pending_provide.remove(&id) {
                    let _ = tx.send(Err(anyhow!(err.to_string())));
                }
            }
            QueryResult::GetProviders(Ok(GetProvidersOk::FoundProviders { key, providers })) => {
                if pending_provider_queries.contains_key(&id) {
                    let provider_records = {
                        let behaviour = swarm.behaviour_mut();
                        behaviour.kademlia.store_mut().providers(&key)
                    };
                    let provider_map: HashMap<PeerId, Vec<Multiaddr>> = provider_records
                        .into_iter()
                        .map(|record| (record.provider, record.addresses))
                        .collect();
                    let mut provider_ids: Vec<_> = providers.into_iter().collect();
                    if provider_ids.is_empty() {
                        provider_ids.extend(provider_map.keys().copied());
                    }
                    provider_ids.sort_by(|a, b| {
                        let score_a = gossipsub_peer_score(swarm, a);
                        let score_b = gossipsub_peer_score(swarm, b);
                        score_b.partial_cmp(&score_a).unwrap_or(Ordering::Equal)
                    });
                    if let Some(state) = pending_provider_queries.get_mut(&id) {
                        let key_bytes = state.key_bytes();
                        let (dial_map, peer_only) =
                            state.note_providers(provider_ids, &provider_map);
                        let local_peer_id = *swarm.local_peer_id();

                        for (peer, addresses) in dial_map {
                            if peer == local_peer_id {
                                continue;
                            }
                            if !gossipsub_peer_is_healthy(swarm, &peer) {
                                let score = gossipsub_peer_score(swarm, &peer);
                                warn!(
                                    target: "p2p",
                                    %peer,
                                    score = score,
                                    "skipping provider with low gossip score"
                                );
                                continue;
                            }
                            provider_dials
                                .entry(peer)
                                .or_default()
                                .insert(key_bytes.clone());
                            let addresses_for_add = addresses.clone();
                            {
                                let behaviour = swarm.behaviour_mut();
                                for addr in &addresses_for_add {
                                    behaviour.kademlia.add_address(&peer, addr.clone());
                                }
                            }
                            let opts = DialOpts::peer_id(peer)
                                .addresses(addresses)
                                .extend_addresses_through_behaviour()
                                .build();
                            if let Err(err) = swarm.dial(opts) {
                                warn!(target: "p2p", %peer, "provider dial failed: {err}");
                            }
                        }

                        for peer in peer_only {
                            if peer == local_peer_id {
                                continue;
                            }
                            if !gossipsub_peer_is_healthy(swarm, &peer) {
                                let score = gossipsub_peer_score(swarm, &peer);
                                warn!(
                                    target: "p2p",
                                    %peer,
                                    score = score,
                                    "skipping provider without addresses due to low gossip score"
                                );
                                continue;
                            }
                            provider_dials
                                .entry(peer)
                                .or_default()
                                .insert(key_bytes.clone());
                            if let Err(err) = swarm.dial(peer) {
                                warn!(
                                    target: "p2p",
                                    %peer,
                                    "provider fallback dial failed: {err}"
                                );
                            }
                        }
                    }
                }
            }
            QueryResult::GetProviders(Ok(GetProvidersOk::FinishedWithNoAdditionalRecord {
                ..
            })) => {
                if let Some(mut state) = pending_provider_queries.remove(&id) {
                    state.absorb_store(swarm);
                    let (response, peers) = state.finish();
                    let filtered_peers: Vec<_> = peers
                        .into_iter()
                        .filter(|peer| {
                            if gossipsub_peer_is_healthy(swarm, &peer.peer_id) {
                                true
                            } else {
                                let score = gossipsub_peer_score(swarm, &peer.peer_id);
                                warn!(
                                    target: "p2p",
                                    peer = %peer.peer_id,
                                    score = score,
                                    "dropping low-score provider from response"
                                );
                                false
                            }
                        })
                        .collect();
                    if let Some(response) = response {
                        let _ = response.send(Ok(filtered_peers));
                    }
                }
            }
            QueryResult::GetProviders(Err(err)) => {
                if let Some(state) = pending_provider_queries.remove(&id) {
                    let ProviderQueryState { response, .. } = state;
                    if let Some(response) = response {
                        let _ = response.send(Err(anyhow!(err.to_string())));
                    }
                }
            }
            _ => {}
        }
    }
}

fn schedule_provider_refresh(
    key: Vec<u8>,
    provider_backoff: &mut HashMap<Vec<u8>, ProviderBackoff>,
    provider_retry: &mut FuturesUnordered<BoxFuture<'static, Vec<u8>>>,
    immediate: bool,
) {
    let entry = provider_backoff.entry(key.clone()).or_default();
    let maybe_delay = if immediate {
        entry.schedule_immediate()
    } else {
        entry.schedule_with_backoff()
    };
    if let Some(delay) = maybe_delay {
        provider_retry.push(Box::pin(async move {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            key
        }));
    }
}

fn build_replication_payload(key: &[u8], value: &[u8]) -> Option<Vec<u8>> {
    let key_len: u16 = u16::try_from(key.len()).ok()?;
    let mut payload = Vec::with_capacity(2 + key.len() + value.len());
    payload.extend_from_slice(&key_len.to_be_bytes());
    payload.extend_from_slice(key);
    payload.extend_from_slice(value);
    Some(payload)
}

fn parse_replication_payload(data: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    if data.len() < 2 {
        return None;
    }
    let len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + len {
        return None;
    }
    let key = data[2..2 + len].to_vec();
    let value = data[2 + len..].to_vec();
    Some((key, value))
}

fn gossipsub_peer_score(swarm: &Swarm<NodeBehaviour>, peer_id: &PeerId) -> f64 {
    swarm
        .behaviour()
        .gossipsub
        .peer_score(peer_id)
        .unwrap_or_default()
}

fn gossipsub_peer_is_healthy(swarm: &Swarm<NodeBehaviour>, peer_id: &PeerId) -> bool {
    gossipsub_peer_score(swarm, peer_id) >= GOSSIP_GRAYLIST_THRESHOLD
}

#[derive(Debug, Error)]
enum SthGossipError {
    #[error("failed to decode STH announcement: {0}")]
    Decode(#[from] serde_cbor::Error),
    #[error("invalid STH announcement: {0}")]
    Validation(#[from] SthValidationError),
}

fn validate_sth_gossip(
    data: &[u8],
    trust: &VkdTrustAnchors,
) -> Result<SthAnnouncement, SthGossipError> {
    let announcement: SthAnnouncement = serde_cbor::from_slice(data)?;
    verify_sth_announcement(&announcement, trust)?;
    Ok(announcement)
}

#[cfg(test)]
mod tests {
    use super::ipfs::{BlockFetcher, DirectBlockFetchError, DirectBlockFetcher, KuboGateway};
    use super::*;
    use crate::quorum::{bls_sign, SIG_DST};
    use crate::{
        generate_directory_record, DirectoryRecord, HandshakeInit, HandshakeResp, MlKem1024,
        TestVkdKeys, VkdProof,
    };
    use anyhow::anyhow;
    use async_trait::async_trait;
    use group::Curve;
    use libipld::prelude::Codec;
    use libipld::{
        cbor::DagCborCodec,
        cid::Cid,
        serde::{from_ipld, to_ipld},
        Ipld,
    };
    use multihash::{Code, MultihashDigest};
    use rand_core_06::{OsRng, RngCore};
    use reqwest::Client;
    use serde::{de::DeserializeOwned, Serialize};
    use std::{
        collections::HashMap,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        },
        time::Duration,
    };
    use tokio::{io::AsyncWriteExt, net::TcpListener, sync::oneshot, task::JoinHandle};

    fn sample_keys() -> TestVkdKeys {
        TestVkdKeys::single_witness()
    }

    fn build_valid_sth_message(keys: &TestVkdKeys) -> Vec<u8> {
        let trust = &keys.trust;
        let log_id = trust.log_id().to_vec();
        let root_hash = [11u8; 32];
        let tree_size = 6u64;
        let sth_time = 13u64;

        let mut tuple = Vec::new();
        tuple.extend_from_slice(&root_hash);
        tuple.extend_from_slice(&tree_size.to_le_bytes());
        tuple.extend_from_slice(&sth_time.to_le_bytes());
        tuple.extend_from_slice(&log_id);

        let log_sig = bls_sign(&keys.log_sk, &tuple, SIG_DST)
            .to_affine()
            .to_compressed()
            .to_vec();
        let witness_sk = keys
            .witness_sks
            .first()
            .expect("at least one witness secret key");
        let witness_sig = bls_sign(witness_sk, &tuple, SIG_DST)
            .to_affine()
            .to_compressed()
            .to_vec();

        let announcement = SthAnnouncement {
            sth_cid: Cid::new_v1(
                u64::from(libipld::cbor::DagCborCodec),
                Code::Sha2_256.digest(b"sth-test"),
            ),
            log_id,
            root_hash,
            tree_size,
            sth_time,
            log_signature: log_sig,
            witness_signatures: vec![witness_sig],
        };

        serde_cbor::to_vec(&announcement).expect("encode sth announcement")
    }

    #[test]
    fn sth_validation_accepts_valid_payload() {
        let keys = sample_keys();
        let data = build_valid_sth_message(&keys);
        assert!(validate_sth_gossip(&data, &keys.trust).is_ok());
    }

    #[test]
    fn sth_validation_rejects_tampered_signature() {
        let keys = sample_keys();
        let mut data = build_valid_sth_message(&keys);
        let mut announcement: SthAnnouncement =
            serde_cbor::from_slice(&data).expect("decode sth announcement");
        if let Some(byte) = announcement.log_signature.first_mut() {
            *byte ^= 0xAA;
        }
        data = serde_cbor::to_vec(&announcement).expect("re-encode tampered announcement");

        match validate_sth_gossip(&data, &keys.trust) {
            Err(SthGossipError::Validation(error)) => {
                assert!(matches!(
                    error,
                    SthValidationError::InvalidLogSignature
                        | SthValidationError::MalformedLogSignature
                ));
            }
            other => panic!("unexpected validation result: {other:?}"),
        }
    }

    async fn wait_for_listen(node: &P2pNode) -> Result<Vec<(PeerId, Multiaddr)>> {
        for _ in 0..40 {
            let addrs = node.listen_addrs().await?;
            if !addrs.is_empty() {
                let peers = addrs
                    .into_iter()
                    .map(|addr| (node.peer_id(), addr))
                    .collect();
                return Ok(peers);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err(anyhow!("missing listen addresses"))
    }

    async fn spawn_connected_pair() -> Result<(P2pNode, P2pNode)> {
        let listen_addr: Multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1".parse()?;
        let keys = sample_keys();
        let trust_arc = Arc::new(keys.trust.clone());
        let node_a_config = P2pConfig {
            listen_addresses: vec![listen_addr.clone()],
            enable_mdns: false,
            vkd_trust: Arc::clone(&trust_arc),
            ..P2pConfig::default()
        };
        let node_a = P2pNode::run(node_a_config).await?;
        let node_a_bootstrap = wait_for_listen(&node_a).await?;

        let node_b_config = P2pConfig {
            listen_addresses: vec![listen_addr],
            enable_mdns: false,
            bootstrap_peers: node_a_bootstrap.clone(),
            vkd_trust: Arc::clone(&trust_arc),
            ..P2pConfig::default()
        };
        let node_b = P2pNode::run(node_b_config).await?;

        node_b.bootstrap(&node_a_bootstrap).await?;
        let node_b_bootstrap = wait_for_listen(&node_b).await?;
        node_a.bootstrap(&node_b_bootstrap).await?;

        tokio::time::sleep(Duration::from_secs(2)).await;
        Ok((node_a, node_b))
    }

    async fn spawn_connected_nodes(count: usize) -> Result<Vec<P2pNode>> {
        assert!(count >= 1, "at least one node required");
        let mut nodes: Vec<P2pNode> = Vec::with_capacity(count);
        let mut listen_sets: Vec<Vec<(PeerId, Multiaddr)>> = Vec::with_capacity(count);

        for index in 0..count {
            let listen_addr: Multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1".parse()?;
            let bootstrap_peers = if index > 0 {
                let mut peers = Vec::new();
                for addresses in &listen_sets {
                    peers.extend_from_slice(addresses);
                }
                peers
            } else {
                Vec::new()
            };
            let keys = sample_keys();
            let trust_arc = Arc::new(keys.trust);
            let config = P2pConfig {
                listen_addresses: vec![listen_addr],
                enable_mdns: false,
                bootstrap_peers,
                vkd_trust: Arc::clone(&trust_arc),
                ..P2pConfig::default()
            };

            let node = P2pNode::run(config).await?;
            let listen_addrs = wait_for_listen(&node).await?;

            for previous in &listen_sets {
                node.bootstrap(previous).await?;
            }
            for existing in &nodes {
                existing.bootstrap(&listen_addrs).await?;
            }

            listen_sets.push(listen_addrs.clone());
            nodes.push(node);
        }

        tokio::time::sleep(Duration::from_secs(2)).await;
        Ok(nodes)
    }

    #[derive(Clone, Default)]
    struct FakeKubo {
        blocks: Arc<Mutex<HashMap<Cid, Vec<u8>>>>,
        ipns: Arc<Mutex<HashMap<String, Cid>>>,
        direct_calls: Arc<AtomicUsize>,
    }

    impl FakeKubo {
        fn new() -> Self {
            Self::default()
        }

        fn store_ipld(&self, ipld: &Ipld) -> Cid {
            let bytes = DagCborCodec.encode(ipld).expect("encode dag-cbor block");
            let multihash = Code::Sha2_256.digest(&bytes);
            let cid = Cid::new_v1(u64::from(DagCborCodec), multihash);
            self.blocks
                .lock()
                .expect("kubo blocks lock")
                .insert(cid, bytes);
            cid
        }

        fn store_dag_cbor<T>(&self, value: &T) -> Cid
        where
            T: Serialize,
        {
            let ipld = to_ipld(value).expect("value to ipld");
            self.store_ipld(&ipld)
        }

        fn store_bytes(&self, data: &[u8]) -> Cid {
            self.store_ipld(&Ipld::Bytes(data.to_vec()))
        }

        fn publish_ipns(&self, name: &str, cid: Cid) {
            self.ipns
                .lock()
                .expect("ipns lock")
                .insert(name.to_string(), cid);
        }

        fn resolve_ipns(&self, name: &str) -> Option<Cid> {
            self.ipns.lock().expect("ipns lock").get(name).cloned()
        }

        fn direct_calls(&self) -> usize {
            self.direct_calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl DirectBlockFetcher for FakeKubo {
        async fn try_fetch_block(
            &self,
            cid: &Cid,
        ) -> Result<Option<Vec<u8>>, DirectBlockFetchError> {
            self.direct_calls.fetch_add(1, Ordering::SeqCst);
            let block = self
                .blocks
                .lock()
                .expect("kubo blocks lock")
                .get(cid)
                .cloned();
            Ok(block)
        }
    }

    async fn spawn_probe_gateway() -> Result<(
        KuboGateway,
        Arc<AtomicUsize>,
        oneshot::Sender<()>,
        JoinHandle<()>,
    )> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let hits = Arc::new(AtomicUsize::new(0));
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let hits_clone = hits.clone();

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    accept = listener.accept() => {
                        match accept {
                            Ok((mut stream, _)) => {
                                hits_clone.fetch_add(1, Ordering::SeqCst);
                                let _ = stream.shutdown().await;
                            }
                            Err(_) => break,
                        }
                    }
                    _ = &mut shutdown_rx => {
                        break;
                    }
                }
            }
        });

        let base = format!("http://{addr}/api/v0/");
        let gateway = KuboGateway::from_str(&base, Duration::from_millis(250))
            .map_err(|error| anyhow!(error.to_string()))?;
        Ok((gateway, hits, shutdown_tx, handle))
    }

    fn decode_dag_cbor<T>(bytes: &[u8]) -> T
    where
        T: DeserializeOwned,
    {
        let ipld = DagCborCodec.decode(bytes).expect("decode dag-cbor payload");
        from_ipld(ipld).expect("deserialize from ipld")
    }

    fn fixture_init() -> HandshakeInit {
        let (record, _) = crate::generate_directory_record::<crate::MlKem1024>(
            b"did:example:alice".to_vec(),
            7,
            crate::sample_quorum_desc(7),
        )
        .expect("generate record");
        let spend = crate::make_receipt(record.prekey_batch_root);
        let keys = TestVkdKeys::single_witness();
        let vkd = crate::make_vkd_proof(&record, &keys);
        let (init, _) =
            crate::initiator_handshake_init::<crate::MlKem1024>(&record, spend, None, vkd)
                .expect("handshake init");
        init
    }

    fn fixture_resp() -> HandshakeResp {
        HandshakeResp {
            nonce: [9_u8; 12],
            confirm_tag: vec![1, 2, 3, 4],
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn smoke_test_record_and_gossip() -> Result<()> {
        let _ = tracing_subscriber::fmt::try_init();

        let (node_a, node_b) = spawn_connected_pair().await?;

        let mut topic_rx = node_b.subscribe("test-topic").await?;
        node_a.subscribe("test-topic").await?;

        let mut record_key = vec![0_u8; 32];
        OsRng.fill_bytes(&mut record_key);
        let record_value = b"hello world".to_vec();

        node_a
            .put_record(record_key.clone(), record_value.clone())
            .await?;
        tokio::time::sleep(Duration::from_secs(2)).await;

        let mut received = None;
        for _ in 0..10 {
            if let Some(value) = node_b.get_record(record_key.clone()).await? {
                received = Some(value);
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        assert_eq!(received, Some(record_value.clone()));

        node_a.publish("test-topic", b"ping".to_vec()).await?;

        let mut got_message = false;
        let timeout = tokio::time::sleep(Duration::from_secs(5));
        tokio::pin!(timeout);
        while !got_message {
            tokio::select! {
                Ok(message) = topic_rx.recv() => {
                    if message.data == b"ping".to_vec() {
                        got_message = true;
                    }
                }
                _ = &mut timeout => {
                    break;
                }
            }
        }

        assert!(got_message, "did not receive gossip message");

        node_a.stop().await?;
        node_b.stop().await?;

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn exchange_handshake_roundtrip() -> Result<()> {
        let (node_a, node_b) = spawn_connected_pair().await?;
        let initiator_id = node_a.peer_id();
        let responder_id = node_b.peer_id();

        let init = fixture_init();
        let expected_bind = init.transcript_bind;
        let expected_did = init.did.clone();
        let response_payload = fixture_resp();

        let request_future = node_a
            .send_exchange_request(responder_id, ExchangeRequest::HandshakeInit(Box::new(init)));

        let responder = {
            let node_b = &node_b;
            let expected_did = expected_did.clone();
            let response_payload = response_payload.clone();
            let initiator = initiator_id;
            async move {
                let mut events = node_b.exchange_events();
                let inbound = events.recv().await.expect("inbound event");
                let request_id = match inbound {
                    ExchangeEvent::InboundRequest {
                        peer,
                        request_id,
                        request,
                    } => {
                        assert_eq!(peer, initiator);
                        match request {
                            ExchangeRequest::HandshakeInit(msg) => {
                                assert_eq!(msg.did, expected_did);
                                assert_eq!(msg.transcript_bind, expected_bind);
                            }
                            other => panic!("unexpected request variant: {other:?}"),
                        }
                        request_id
                    }
                    other => panic!("unexpected exchange event: {other:?}"),
                };

                node_b
                    .respond_exchange(
                        request_id,
                        ExchangeResponse::HandshakeResp(response_payload),
                    )
                    .await
                    .expect("respond exchange");

                let response_event = events.recv().await.expect("response sent event");
                (request_id, response_event)
            }
        };

        let (response_result, (request_id, response_event)) =
            tokio::join!(request_future, responder);

        let response = response_result.expect("handshake response");
        match response {
            ExchangeResponse::HandshakeResp(resp) => {
                assert_eq!(resp.confirm_tag, response_payload.confirm_tag);
            }
            other => panic!("unexpected response variant: {other:?}"),
        }

        match response_event {
            ExchangeEvent::ResponseSent {
                peer,
                request_id: sent,
            } => {
                assert_eq!(peer, initiator_id);
                assert_eq!(sent, request_id);
            }
            other => panic!("unexpected event after response: {other:?}"),
        }

        node_a.stop().await?;
        node_b.stop().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn rendezvous_advertise_and_discover() -> Result<()> {
        let (node_a, node_b) = spawn_connected_pair().await?;
        let did = "did:example:alice";

        node_a.advertise_rendezvous(did).await?;

        let local_providers = node_a.discover_by_did(did).await?;
        assert!(
            local_providers
                .iter()
                .any(|peer| peer.peer_id == node_a.peer_id()),
            "local provider should include self"
        );

        tokio::time::sleep(Duration::from_secs(1)).await;

        if let Ok(remote) =
            tokio::time::timeout(Duration::from_secs(5), node_b.discover_by_did(did)).await
        {
            let _ = remote?;
        }

        node_a.stop().await?;
        node_b.stop().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn provider_refresh_uses_exponential_backoff() {
        use futures::StreamExt;
        use tokio::time::{timeout, Instant};

        let key = vec![0xAA];
        let mut backoff_map: HashMap<Vec<u8>, ProviderBackoff> = HashMap::new();
        let mut queue: FuturesUnordered<BoxFuture<'static, Vec<u8>>> = FuturesUnordered::new();

        let start = Instant::now();
        schedule_provider_refresh(key.clone(), &mut backoff_map, &mut queue, false);
        let scheduled = timeout(
            Duration::from_millis(PROVIDER_RETRY_BASE_MS * 3),
            queue.next(),
        )
        .await
        .expect("first refresh scheduled")
        .expect("refresh payload");
        assert_eq!(scheduled, key);
        assert!(start.elapsed() >= Duration::from_millis(PROVIDER_RETRY_BASE_MS));
        backoff_map
            .get_mut(&key)
            .expect("backoff entry")
            .mark_triggered();
        assert!(!backoff_map.get(&key).expect("entry").pending);

        let start = Instant::now();
        schedule_provider_refresh(key.clone(), &mut backoff_map, &mut queue, false);
        let scheduled = timeout(
            Duration::from_millis(PROVIDER_RETRY_MAX_MS * 2),
            queue.next(),
        )
        .await
        .expect("second refresh scheduled")
        .expect("refresh payload");
        assert_eq!(scheduled, key);
        assert!(
            start.elapsed()
                >= Duration::from_millis((PROVIDER_RETRY_BASE_MS * 2).min(PROVIDER_RETRY_MAX_MS))
        );
        backoff_map
            .get_mut(&key)
            .expect("backoff entry")
            .mark_triggered();
        assert!(!backoff_map.get(&key).expect("entry").pending);

        schedule_provider_refresh(key.clone(), &mut backoff_map, &mut queue, true);
        let scheduled = timeout(Duration::from_millis(50), queue.next())
            .await
            .expect("immediate refresh scheduled")
            .expect("refresh payload");
        assert_eq!(scheduled, key);
        assert!(backoff_map.get(&key).expect("entry").pending);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn end_to_end_proof_and_bundle_fetch_without_http() -> Result<()> {
        let _ = tracing_subscriber::fmt::try_init();

        let kubo = FakeKubo::new();

        let quorum_desc = crate::quorum::QuorumDescriptor {
            sig_algo: "BLS12381G1_XMD:SHA-256_SSWU_RO".to_string(),
            member_set_hash: [0x11; 32],
            epoch: 7,
        };
        let did = b"did:example:alice".to_vec();
        let (record, _) = generate_directory_record::<MlKem1024>(
            did.clone(),
            quorum_desc.epoch,
            quorum_desc.clone(),
        )
        .expect("generate directory record");
        let bundle_cid = kubo.store_dag_cbor(&record);
        let quorum_cid = kubo.store_dag_cbor(&quorum_desc);

        let mut proof_map = std::collections::BTreeMap::new();
        proof_map.insert("index".into(), Ipld::Integer(0));
        let sibling = Ipld::List((0..32).map(|_| Ipld::Integer(0xAA)).collect());
        proof_map.insert("siblings".into(), Ipld::List(vec![sibling]));
        let inclusion_proof: crate::directory::MerkleProof =
            from_ipld(Ipld::Map(proof_map)).expect("construct proof");

        let proof = VkdProof {
            log_id: b"vkd-test".to_vec(),
            sth_root_hash: [0x22; 32],
            sth_tree_size: 1,
            sth_time: 777,
            sth_sig: vec![0x33, 0x44, 0x55],
            witness_sigs: vec![vec![0x66, 0x77, 0x88]],
            inclusion_hash: [0x99; 32],
            inclusion_proof,
            consistency_proof: None,
            vrf_proof: vec![0xBB, 0xCC, 0xDD],
            bundle_cid,
            quorum_desc_cid: quorum_cid,
        };
        let proof_cid = kubo.store_dag_cbor(&proof);
        kubo.publish_ipns("proof.latest", proof_cid);

        let sth_payload = vec![0x42; 32];
        let sth_cid = kubo.store_bytes(&sth_payload);
        kubo.publish_ipns("sth.latest", sth_cid);

        let mut init = fixture_init();
        init.did = did;
        init.epoch = record.epoch;
        init.prekey_batch_root = record.prekey_batch_root;
        init.bundle_cid = bundle_cid;
        init.sth_cid = sth_cid;
        init.vkd_proof = proof.clone();

        let mut nodes = spawn_connected_nodes(3).await?;
        let node_c = nodes.pop().expect("node c");
        let node_b = nodes.pop().expect("node b");
        let node_a = nodes.pop().expect("node a");

        let (gateway, hits, shutdown_tx, gateway_handle) = spawn_probe_gateway().await?;
        let fetcher = Arc::new(BlockFetcher::with_client(
            kubo.clone(),
            Client::new(),
            vec![gateway],
        ));
        let response_payload = fixture_resp();

        let request_future = node_a.send_exchange_request(
            node_b.peer_id(),
            ExchangeRequest::HandshakeInit(Box::new(init.clone())),
        );

        let responder = {
            let node_b = &node_b;
            let fetcher = fetcher.clone();
            let kubo = kubo.clone();
            let response_payload = response_payload.clone();
            let expected_peer = node_a.peer_id();
            let expected_sth = sth_payload.clone();
            async move {
                let mut events = node_b.exchange_events();
                let inbound = events.recv().await.expect("inbound exchange event");
                let (request_id, fetched_bundle, fetched_proof, fetched_sth) = match inbound {
                    ExchangeEvent::InboundRequest {
                        peer,
                        request_id,
                        request,
                    } => {
                        assert_eq!(peer, expected_peer, "unexpected initiator peer");
                        match request {
                            ExchangeRequest::HandshakeInit(message) => {
                                let bundle_cid = message.bundle_cid;
                                let sth_cid = message.sth_cid;
                                let bundle_bytes = fetcher
                                    .fetch_block(&bundle_cid)
                                    .await
                                    .expect("bundle fetch");
                                let fetched_bundle: DirectoryRecord<MlKem1024> =
                                    decode_dag_cbor(&bundle_bytes);

                                let sth_bytes =
                                    fetcher.fetch_block(&sth_cid).await.expect("sth fetch");
                                let fetched_sth = match DagCborCodec
                                    .decode(&sth_bytes)
                                    .expect("decode sth block")
                                {
                                    Ipld::Bytes(bytes) => bytes,
                                    other => {
                                        from_ipld(other).expect("deserialize sth payload from ipld")
                                    }
                                };

                                let proof_pointer =
                                    kubo.resolve_ipns("proof.latest").expect("proof ipns");
                                let proof_bytes = fetcher
                                    .fetch_block(&proof_pointer)
                                    .await
                                    .expect("proof fetch");
                                let fetched_proof: VkdProof = decode_dag_cbor(&proof_bytes);
                                (request_id, fetched_bundle, fetched_proof, fetched_sth)
                            }
                            other => panic!("unexpected request: {other:?}"),
                        }
                    }
                    other => panic!("unexpected exchange event: {other:?}"),
                };

                node_b
                    .respond_exchange(
                        request_id,
                        ExchangeResponse::HandshakeResp(response_payload),
                    )
                    .await?;
                let response_event = events.recv().await.expect("response sent event");
                assert_eq!(fetched_sth, expected_sth, "retrieved STH payload mismatch");
                Ok::<_, anyhow::Error>((
                    request_id,
                    response_event,
                    fetched_bundle,
                    fetched_proof,
                    fetched_sth,
                ))
            }
        };

        let (response_result, responder_result) = tokio::join!(request_future, responder);

        let response = response_result.expect("handshake response");
        match response {
            ExchangeResponse::HandshakeResp(_) => {}
            other => panic!("unexpected handshake response: {other:?}"),
        }

        let responder_data = match responder_result {
            Ok(data) => data,
            Err(error) => {
                node_a.stop().await?;
                node_b.stop().await?;
                node_c.stop().await?;
                let _ = shutdown_tx.send(());
                let _ = gateway_handle.await;
                return Err(error);
            }
        };

        let (request_id, response_event, fetched_bundle, fetched_proof, fetched_sth) =
            responder_data;
        match response_event {
            ExchangeEvent::ResponseSent {
                peer,
                request_id: sent,
            } => {
                assert_eq!(peer, node_a.peer_id());
                assert_eq!(sent, request_id);
            }
            other => panic!("unexpected event after response: {other:?}"),
        }

        assert_eq!(fetched_bundle.did, record.did);
        assert_eq!(fetched_bundle.epoch, record.epoch);
        assert_eq!(fetched_bundle.x25519_prekey, record.x25519_prekey);
        assert_eq!(fetched_proof.log_id, proof.log_id);
        assert_eq!(fetched_proof.bundle_cid, bundle_cid);
        assert_eq!(fetched_proof.quorum_desc_cid, quorum_cid);
        assert_eq!(fetched_sth, sth_payload);

        node_a.stop().await?;
        node_b.stop().await?;
        node_c.stop().await?;

        let _ = shutdown_tx.send(());
        let _ = gateway_handle.await;

        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "HTTP gateway should remain unused"
        );
        assert!(
            kubo.direct_calls() >= 3,
            "expected at least three direct fetches"
        );

        Ok(())
    }
}
