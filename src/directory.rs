// This file is part of Chhaya and is licensed under the GNU Affero General Public License v3.0 or later.
// See the LICENSE file in the project root for license details.

use crate::pin::PinPolicy;
use crate::quorum::QuorumDescriptor;
use crate::Kem;
use crate::{record_fingerprint, Did, DirectoryRecord};
use anyhow::{anyhow, Context, Error, Result};
use libipld::{
    cbor::DagCborCodec,
    cid::Cid,
    codec::Codec,
    serde::{from_ipld, to_ipld},
    Ipld,
};
use multihash::{Code, MultihashDigest};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::convert::{TryFrom, TryInto};
use std::io::{self, Cursor, Read, Write};
use std::time::{Duration, Instant};

fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            if let Some(&last) = level.last() {
                level.push(last);
            }
        }
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            next.push(hash_pair(&pair[0], &pair[1]));
        }
        level = next;
    }
    level[0]
}

fn write_uvarint<W: Write>(writer: &mut W, mut value: u64) -> io::Result<()> {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        writer.write_all(&[byte])?;
        if value == 0 {
            break;
        }
    }
    Ok(())
}

fn read_uvarint<R: Read>(reader: &mut R) -> io::Result<Option<u64>> {
    let mut value = 0u64;
    let mut shift = 0u32;
    let mut first_byte = true;
    loop {
        let mut buf = [0u8; 1];
        match reader.read_exact(&mut buf) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof && first_byte => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        }
        first_byte = false;
        let byte = buf[0];
        value |= u64::from(byte & 0x7F) << shift;
        if (byte & 0x80) == 0 {
            return Ok(Some(value));
        }
        shift = shift
            .checked_add(7)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "varint overflow"))?;
        if shift >= 64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "varint exceeds 64-bit width",
            ));
        }
    }
}

const CAR_VERSION: u64 = 1;

const DIRECTORY_SNAPSHOT_VERSION: u64 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LogSnapshot {
    leaves: Vec<[u8; 32]>,
    store_leaves: Vec<(Cid, [u8; 32])>,
    last_root: Option<(Cid, [u8; 32])>,
    ipns_records: Vec<(String, Cid)>,
    pin_policy: PinPolicy,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RecordSnapshotEntry {
    bundle_cid: Cid,
    quorum_desc_cid: Cid,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DirectorySnapshot {
    version: u64,
    records: Vec<RecordSnapshotEntry>,
    log: LogSnapshot,
}

fn hash_pair(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(a);
    hasher.update(b);
    let o = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&o);
    out
}

/// Position and sibling hashes proving membership in the transparency log.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleProof {
    index: usize,
    siblings: Vec<[u8; 32]>,
}

impl MerkleProof {
    /// Verifies that `leaf` hashes to `root` given the stored siblings.
    pub fn verify(&self, leaf: [u8; 32], root: [u8; 32]) -> bool {
        let mut hash = leaf;
        let mut idx = self.index;
        for sib in &self.siblings {
            if idx % 2 == 0 {
                hash = hash_pair(&hash, sib);
            } else {
                hash = hash_pair(sib, &hash);
            }
            idx /= 2;
        }
        hash == root
    }

    pub fn siblings(&self) -> &[[u8; 32]] {
        &self.siblings
    }
}

/// Append-only Merkle log anchoring directory record history.
#[derive(Clone, Debug)]
pub struct TransparencyLog {
    leaves: Vec<[u8; 32]>,
    store: IpldLogStore,
    pin_policy: PinPolicy,
}

impl TransparencyLog {
    pub fn new() -> Self {
        Self {
            leaves: Vec::new(),
            store: IpldLogStore::default(),
            pin_policy: PinPolicy::default(),
        }
    }

    pub fn append(&mut self, leaf: [u8; 32]) -> Result<usize> {
        let (index, _) = self.put_leaf(leaf)?;
        Ok(index)
    }

    pub fn put_leaf(&mut self, leaf: [u8; 32]) -> Result<(usize, Cid)> {
        let cid = self.store.put_leaf(leaf)?;
        self.leaves.push(leaf);
        let index = self.leaves.len() - 1;
        Ok((index, cid))
    }

    pub fn commit_root(&mut self) -> Result<Cid> {
        self.store.commit_root()
    }

    pub fn store_directory_record<K: Kem>(&mut self, record: &DirectoryRecord<K>) -> Result<Cid> {
        let cid = self.store.store_dag_cbor(record)?;
        self.pin_policy.add_active_bundle(cid);
        Ok(cid)
    }

    pub fn publish_did_latest(&mut self, did: &[u8], cid: &Cid) -> Result<()> {
        let name = std::str::from_utf8(did).context("invalid UTF-8 DID for IPNS publication")?;
        self.store.publish_ipns(name, *cid);
        Ok(())
    }

    pub fn resolve_did_latest(&self, did: &[u8]) -> Result<Option<Cid>> {
        let name = std::str::from_utf8(did).context("invalid UTF-8 DID for IPNS resolution")?;
        Ok(self.store.resolve_ipns(name))
    }

    pub fn store_quorum_descriptor(&mut self, desc: &QuorumDescriptor) -> Result<Cid> {
        let cid = self.store.store_dag_cbor(desc)?;
        self.pin_policy.add_active_bundle(cid);
        Ok(cid)
    }

    pub fn get_node(&self, cid: &Cid) -> Result<LogNode> {
        self.store.get_node(cid)
    }

    pub fn root(&self) -> [u8; 32] {
        merkle_root(&self.leaves)
    }

    pub fn last_committed_root(&self) -> Option<(Cid, [u8; 32])> {
        self.store.last_root()
    }

    pub fn publish_signed_tree_head(&mut self, sth: &SignedTreeHead) -> Result<Cid> {
        let cid = self.store.store_sth(sth)?;
        self.store.publish_ipns(STH_LATEST_IPNS, cid);
        self.pin_policy
            .update_current_sth(sth.root_cid, sth.tree_size);
        Ok(cid)
    }

    pub fn pin_policy(&self) -> &PinPolicy {
        &self.pin_policy
    }

    pub fn pin_policy_mut(&mut self) -> &mut PinPolicy {
        &mut self.pin_policy
    }

    pub fn export_car<W: Write>(&self, roots: &[Cid], writer: W) -> Result<()> {
        self.store.export_car(roots, writer)
    }

    pub fn import_car<R: Read>(&mut self, reader: R) -> Result<Vec<Cid>> {
        self.store.import_car(reader)
    }

    fn store_snapshot(&mut self, snapshot: &DirectorySnapshot) -> Result<Cid> {
        self.store.store_dag_cbor(snapshot)
    }

    fn load_directory_snapshot(&self, cid: &Cid) -> Result<DirectorySnapshot> {
        self.store.load_dag_cbor(cid)
    }

    fn snapshot_metadata(&self) -> LogSnapshot {
        LogSnapshot {
            leaves: self.leaves.clone(),
            store_leaves: self.store.leaves.clone(),
            last_root: self.store.last_root,
            ipns_records: self
                .store
                .ipns_records
                .iter()
                .map(|(name, cid)| (name.clone(), *cid))
                .collect(),
            pin_policy: self.pin_policy.clone(),
        }
    }

    fn apply_snapshot(&mut self, snapshot: &LogSnapshot) {
        self.leaves = snapshot.leaves.clone();
        self.store.leaves = snapshot.store_leaves.clone();
        self.store.last_root = snapshot.last_root;
        self.store.ipns_records = snapshot
            .ipns_records
            .iter()
            .cloned()
            .collect::<HashMap<_, _>>();
        self.pin_policy = snapshot.pin_policy.clone();
    }

    fn load_directory_record<K: Kem>(&self, cid: &Cid) -> Result<DirectoryRecord<K>> {
        self.store.load_dag_cbor(cid)
    }

    fn load_quorum_descriptor(&self, cid: &Cid) -> Result<QuorumDescriptor> {
        self.store.load_dag_cbor(cid)
    }

    fn reset(&mut self) {
        self.leaves.clear();
        self.store.leaves.clear();
        self.store.last_root = None;
        self.store.ipns_records.clear();
        self.pin_policy = PinPolicy::default();
    }

    pub fn fetch_latest_sth(&self) -> Result<Option<SignedTreeHead>> {
        let Some(cid) = self.store.resolve_ipns(STH_LATEST_IPNS) else {
            return Ok(None);
        };
        let sth = self.store.get_sth(&cid)?;
        Ok(Some(sth))
    }

    pub fn prove(&self, index: usize) -> Option<MerkleProof> {
        if index >= self.leaves.len() {
            return None;
        }
        let mut level: Vec<[u8; 32]> = self.leaves.clone();
        let mut idx = index;
        let mut siblings = Vec::new();
        while level.len() > 1 {
            if level.len() % 2 == 1 {
                if let Some(&last) = level.last() {
                    level.push(last);
                }
            }
            let sib = idx ^ 1;
            siblings.push(level[sib]);
            idx /= 2;
            let mut next = Vec::with_capacity(level.len() / 2);
            for pair in level.chunks(2) {
                next.push(hash_pair(&pair[0], &pair[1]));
            }
            level = next;
        }
        Some(MerkleProof { index, siblings })
    }
}

impl Default for TransparencyLog {
    fn default() -> Self {
        Self::new()
    }
}

/// Nodes persisted in IPLD representing a transparency log tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogNode {
    Leaf {
        fingerprint: [u8; 32],
    },
    Branch {
        left: Cid,
        right: Cid,
        hash: [u8; 32],
    },
    Empty {
        hash: [u8; 32],
    },
}

impl LogNode {
    fn hash(&self) -> [u8; 32] {
        match self {
            Self::Leaf { fingerprint } => *fingerprint,
            Self::Branch { hash, .. } => *hash,
            Self::Empty { hash } => *hash,
        }
    }

    fn to_ipld(&self) -> Ipld {
        let mut map = BTreeMap::new();
        match self {
            Self::Leaf { fingerprint } => {
                map.insert("type".to_string(), Ipld::String("leaf".into()));
                map.insert("fingerprint".to_string(), Ipld::Bytes(fingerprint.to_vec()));
            }
            Self::Branch { left, right, hash } => {
                map.insert("type".to_string(), Ipld::String("branch".into()));
                map.insert("left".to_string(), Ipld::Link(*left));
                map.insert("right".to_string(), Ipld::Link(*right));
                map.insert("hash".to_string(), Ipld::Bytes(hash.to_vec()));
            }
            Self::Empty { hash } => {
                map.insert("type".to_string(), Ipld::String("empty".into()));
                map.insert("hash".to_string(), Ipld::Bytes(hash.to_vec()));
            }
        }
        Ipld::Map(map)
    }

    fn from_ipld(ipld: Ipld) -> Result<Self> {
        let map = match ipld {
            Ipld::Map(map) => map,
            _ => return Err(anyhow!("log node must be a map")),
        };
        let node_type = match map.get("type") {
            Some(Ipld::String(kind)) => kind.as_str(),
            _ => return Err(anyhow!("log node missing type field")),
        };
        match node_type {
            "leaf" => {
                let fingerprint = Self::bytes32(&map, "fingerprint")?;
                Ok(Self::Leaf { fingerprint })
            }
            "branch" => {
                let left = Self::link(&map, "left")?;
                let right = Self::link(&map, "right")?;
                let hash = Self::bytes32(&map, "hash")?;
                Ok(Self::Branch { left, right, hash })
            }
            "empty" => {
                let hash = Self::bytes32(&map, "hash")?;
                Ok(Self::Empty { hash })
            }
            other => Err(anyhow!("unknown log node type {other}")),
        }
    }

    fn bytes32(map: &BTreeMap<String, Ipld>, key: &str) -> Result<[u8; 32]> {
        let value = map
            .get(key)
            .ok_or_else(|| anyhow!("log node missing {key} field"))?;
        let bytes = match value {
            Ipld::Bytes(bytes) => bytes,
            _ => return Err(anyhow!("log node field {key} must be bytes")),
        };
        let slice: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("log node field {key} must be 32 bytes"))?;
        Ok(slice)
    }

    fn link(map: &BTreeMap<String, Ipld>, key: &str) -> Result<Cid> {
        match map.get(key) {
            Some(Ipld::Link(cid)) => Ok(*cid),
            _ => Err(anyhow!("log node field {key} must be a CID link")),
        }
    }
}

/// Signed commitment to the transparency log's current state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedTreeHead {
    pub log_id: Vec<u8>,
    pub root_hash: [u8; 32],
    pub tree_size: u64,
    pub sth_time: u64,
    pub root_cid: Cid,
    pub log_signature: Vec<u8>,
    pub witness_signatures: Vec<Vec<u8>>,
}

impl SignedTreeHead {
    fn to_ipld(&self) -> Ipld {
        let mut map = BTreeMap::new();
        map.insert("type".to_string(), Ipld::String("sth".into()));
        map.insert("log_id".to_string(), Ipld::Bytes(self.log_id.clone()));
        map.insert(
            "root_hash".to_string(),
            Ipld::Bytes(self.root_hash.to_vec()),
        );
        map.insert(
            "tree_size".to_string(),
            Ipld::Integer(i128::from(self.tree_size)),
        );
        map.insert(
            "sth_time".to_string(),
            Ipld::Integer(i128::from(self.sth_time)),
        );
        map.insert("root".to_string(), Ipld::Link(self.root_cid));
        map.insert(
            "log_signature".to_string(),
            Ipld::Bytes(self.log_signature.clone()),
        );
        let witnesses = self
            .witness_signatures
            .iter()
            .cloned()
            .map(Ipld::Bytes)
            .collect();
        map.insert("witness_signatures".to_string(), Ipld::List(witnesses));
        Ipld::Map(map)
    }

    fn from_ipld(ipld: Ipld) -> Result<Self> {
        let map = match ipld {
            Ipld::Map(map) => map,
            _ => return Err(anyhow!("signed tree head must be a map")),
        };
        let node_type = match map.get("type") {
            Some(Ipld::String(kind)) => kind.as_str(),
            _ => return Err(anyhow!("signed tree head missing type field")),
        };
        if node_type != "sth" {
            return Err(anyhow!("unexpected signed tree head type {node_type}"));
        }
        let log_id = match map.get("log_id") {
            Some(Ipld::Bytes(bytes)) => bytes.clone(),
            _ => return Err(anyhow!("signed tree head field log_id must be bytes")),
        };
        let root_hash = Self::bytes32(&map, "root_hash")?;
        let tree_size = Self::u64(&map, "tree_size")?;
        let sth_time = Self::u64(&map, "sth_time")?;
        let root_cid = match map.get("root") {
            Some(Ipld::Link(cid)) => *cid,
            _ => return Err(anyhow!("signed tree head field root must be a CID link")),
        };
        let log_signature = match map.get("log_signature") {
            Some(Ipld::Bytes(bytes)) => bytes.clone(),
            _ => {
                return Err(anyhow!(
                    "signed tree head field log_signature must be bytes"
                ))
            }
        };
        let witness_signatures = match map.get("witness_signatures") {
            Some(Ipld::List(values)) => {
                let mut signatures = Vec::with_capacity(values.len());
                for value in values {
                    match value {
                        Ipld::Bytes(bytes) => signatures.push(bytes.clone()),
                        _ => {
                            return Err(anyhow!(
                                "signed tree head witness signatures must be bytes"
                            ))
                        }
                    }
                }
                signatures
            }
            Some(_) => {
                return Err(anyhow!(
                    "signed tree head field witness_signatures must be a list"
                ))
            }
            None => Vec::new(),
        };
        Ok(Self {
            log_id,
            root_hash,
            tree_size,
            sth_time,
            root_cid,
            log_signature,
            witness_signatures,
        })
    }

    fn bytes32(map: &BTreeMap<String, Ipld>, key: &str) -> Result<[u8; 32]> {
        let value = map
            .get(key)
            .ok_or_else(|| anyhow!("signed tree head missing {key} field"))?;
        let bytes = match value {
            Ipld::Bytes(bytes) => bytes,
            _ => return Err(anyhow!("signed tree head field {key} must be bytes")),
        };
        let slice: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("signed tree head field {key} must be 32 bytes"))?;
        Ok(slice)
    }

    fn u64(map: &BTreeMap<String, Ipld>, key: &str) -> Result<u64> {
        let value = map
            .get(key)
            .ok_or_else(|| anyhow!("signed tree head missing {key} field"))?;
        match value {
            Ipld::Integer(int) if *int >= 0 => u64::try_from(*int)
                .map_err(|_| anyhow!("signed tree head field {key} out of range")),
            _ => Err(anyhow!("signed tree head field {key} must be an integer")),
        }
    }
}

const STH_LATEST_IPNS: &str = "sth.latest";

#[derive(Clone, Debug, Default)]
struct IpldLogStore {
    blocks: HashMap<Cid, Vec<u8>>,
    leaves: Vec<(Cid, [u8; 32])>,
    last_root: Option<(Cid, [u8; 32])>,
    ipns_records: HashMap<String, Cid>,
}

impl IpldLogStore {
    fn put_leaf(&mut self, leaf: [u8; 32]) -> Result<Cid> {
        let node = LogNode::Leaf { fingerprint: leaf };
        let cid = self.store_node(&node)?;
        self.leaves.push((cid, leaf));
        self.last_root = None;
        Ok(cid)
    }

    fn commit_root(&mut self) -> Result<Cid> {
        let mut current = self.leaves.clone();
        if current.is_empty() {
            let node = LogNode::Empty { hash: [0u8; 32] };
            let cid = self.store_node(&node)?;
            self.last_root = Some((cid, node.hash()));
            return Ok(cid);
        }
        while current.len() > 1 {
            if current.len() % 2 == 1 {
                if let Some(&last) = current.last() {
                    current.push(last);
                }
            }
            let mut next = Vec::with_capacity(current.len() / 2);
            for pair in current.chunks(2) {
                let (left_cid, left_hash) = &pair[0];
                let (right_cid, right_hash) = &pair[1];
                let hash = hash_pair(left_hash, right_hash);
                let node = LogNode::Branch {
                    left: *left_cid,
                    right: *right_cid,
                    hash,
                };
                let cid = self.store_node(&node)?;
                next.push((cid, hash));
            }
            current = next;
        }
        let &(root_cid, root_hash) = &current[0];
        self.last_root = Some((root_cid, root_hash));
        Ok(root_cid)
    }

    fn get_node(&self, cid: &Cid) -> Result<LogNode> {
        let ipld = self.load_ipld(cid)?;
        LogNode::from_ipld(ipld)
    }

    fn last_root(&self) -> Option<(Cid, [u8; 32])> {
        self.last_root
    }

    fn store_node(&mut self, node: &LogNode) -> Result<Cid> {
        let ipld = node.to_ipld();
        self.store_ipld(&ipld)
    }

    fn store_sth(&mut self, sth: &SignedTreeHead) -> Result<Cid> {
        let ipld = sth.to_ipld();
        self.store_ipld(&ipld)
    }

    fn store_dag_cbor<T>(&mut self, value: &T) -> Result<Cid>
    where
        T: Serialize,
    {
        let ipld = to_ipld(value)?;
        self.store_ipld(&ipld)
    }

    fn get_sth(&self, cid: &Cid) -> Result<SignedTreeHead> {
        let ipld = self.load_ipld(cid)?;
        SignedTreeHead::from_ipld(ipld)
    }

    fn publish_ipns(&mut self, name: &str, cid: Cid) {
        self.ipns_records.insert(name.to_string(), cid);
    }

    fn resolve_ipns(&self, name: &str) -> Option<Cid> {
        self.ipns_records.get(name).copied()
    }

    fn store_ipld(&mut self, ipld: &Ipld) -> Result<Cid> {
        let bytes = DagCborCodec.encode(ipld)?;
        Ok(self.store_bytes(bytes))
    }

    fn load_ipld(&self, cid: &Cid) -> Result<Ipld> {
        let bytes = self
            .blocks
            .get(cid)
            .ok_or_else(|| anyhow!("missing block for cid {cid}"))?;
        DagCborCodec.decode(bytes.as_slice())
    }

    fn store_bytes(&mut self, bytes: Vec<u8>) -> Cid {
        let multihash = Code::Sha2_256.digest(&bytes);
        let cid = Cid::new_v1(u64::from(DagCborCodec), multihash);
        self.blocks.entry(cid).or_insert(bytes);
        cid
    }

    fn load_dag_cbor<T>(&self, cid: &Cid) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let ipld = self.load_ipld(cid)?;
        Ok(from_ipld(ipld)?)
    }

    fn clear(&mut self) {
        self.blocks.clear();
        self.leaves.clear();
        self.last_root = None;
        self.ipns_records.clear();
    }

    fn export_car<W: Write>(&self, roots: &[Cid], mut writer: W) -> Result<()> {
        let mut header_map = BTreeMap::new();
        header_map.insert(
            "version".to_string(),
            Ipld::Integer(i128::from(CAR_VERSION)),
        );
        let roots_list = roots.iter().copied().map(Ipld::Link).collect();
        header_map.insert("roots".to_string(), Ipld::List(roots_list));
        let header = Ipld::Map(header_map);
        let header_bytes = DagCborCodec.encode(&header)?;
        write_uvarint(&mut writer, header_bytes.len() as u64)?;
        writer.write_all(&header_bytes)?;

        let mut entries: Vec<_> = self.blocks.iter().collect();
        entries.sort_by(|(a, _), (b, _)| a.to_bytes().cmp(&b.to_bytes()));

        for (cid, block) in entries {
            let mut data = cid.to_bytes();
            data.extend_from_slice(block);
            write_uvarint(&mut writer, data.len() as u64)?;
            writer.write_all(&data)?;
        }
        Ok(())
    }

    fn import_car<R: Read>(&mut self, mut reader: R) -> Result<Vec<Cid>> {
        self.clear();

        let header_len =
            read_uvarint(&mut reader)?.ok_or_else(|| anyhow!("CAR stream missing header"))?;
        let mut header_bytes = vec![0u8; header_len as usize];
        reader
            .read_exact(&mut header_bytes)
            .context("failed to read CAR header")?;
        let header_ipld = DagCborCodec
            .decode(&header_bytes)
            .context("invalid CAR header encoding")?;
        let header_map = match header_ipld {
            Ipld::Map(map) => map,
            _ => return Err(anyhow!("CAR header must be a map")),
        };
        let version = match header_map.get("version") {
            Some(Ipld::Integer(value)) if *value >= 0 => *value as u64,
            _ => return Err(anyhow!("CAR header missing version")),
        };
        if version != CAR_VERSION {
            return Err(anyhow!("unsupported CAR version {version}"));
        }
        let roots_field = header_map
            .get("roots")
            .ok_or_else(|| anyhow!("CAR header missing roots"))?;
        let roots_list = match roots_field {
            Ipld::List(list) => list,
            _ => return Err(anyhow!("CAR header roots must be a list")),
        };
        let mut roots = Vec::with_capacity(roots_list.len());
        for value in roots_list {
            let cid = match value {
                Ipld::Link(cid) => *cid,
                _ => return Err(anyhow!("CAR root entries must be CID links")),
            };
            roots.push(cid);
        }

        while let Some(block_len) = read_uvarint(&mut reader)? {
            let mut data = vec![0u8; block_len as usize];
            reader
                .read_exact(&mut data)
                .context("failed to read CAR block")?;
            let mut cursor = Cursor::new(&data);
            let cid = Cid::read_bytes(&mut cursor).context("invalid block CID")?;
            let mut block_bytes = Vec::new();
            cursor
                .read_to_end(&mut block_bytes)
                .context("failed to read block data")?;
            self.blocks.insert(cid, block_bytes);
        }

        Ok(roots)
    }
}

/// Materialized key directory contents along with verification metadata.
#[derive(Default, Clone, Debug)]
pub struct KeyDirectory<K: Kem> {
    records: Vec<DirectoryRecord<K>>,
    log: TransparencyLog,
    did_cache: HashMap<Did, DidCacheEntry>,
}

impl<K: Kem> KeyDirectory<K> {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            log: TransparencyLog::new(),
            did_cache: HashMap::new(),
        }
    }

    pub fn insert(&mut self, mut record: DirectoryRecord<K>) -> Result<usize> {
        let bundle_cid = self.log.store_directory_record(&record)?;
        let quorum_cid = self.log.store_quorum_descriptor(&record.quorum_desc)?;
        record.bundle_cid = Some(bundle_cid);
        record.quorum_desc_cid = Some(quorum_cid);
        self.log.publish_did_latest(&record.did, &bundle_cid)?;
        let now = Instant::now();
        let cache_key = record.did.clone();
        self.did_cache
            .insert(cache_key, DidCacheEntry::new(bundle_cid, now));
        let fp = record_fingerprint(&record);
        let idx = self.log.append(fp)?;
        self.records.push(record);
        Ok(idx)
    }

    pub fn get(&self, index: usize) -> Option<&DirectoryRecord<K>> {
        self.records.get(index)
    }

    pub fn prove(&self, index: usize) -> Option<MerkleProof> {
        self.log.prove(index)
    }

    pub fn root(&self) -> [u8; 32] {
        self.log.root()
    }

    pub fn commit_root(&mut self) -> Result<Cid> {
        self.log.commit_root()
    }

    pub fn get_log_node(&self, cid: &Cid) -> Result<LogNode> {
        self.log.get_node(cid)
    }

    pub fn last_committed_root(&self) -> Option<(Cid, [u8; 32])> {
        self.log.last_committed_root()
    }

    pub fn fetch_latest_sth(&self) -> Result<Option<SignedTreeHead>> {
        self.log.fetch_latest_sth()
    }

    pub fn pin_policy(&self) -> &PinPolicy {
        self.log.pin_policy()
    }

    pub fn pin_policy_mut(&mut self) -> &mut PinPolicy {
        self.log.pin_policy_mut()
    }

    pub fn create_snapshot(&mut self) -> Result<Cid> {
        let mut entries = Vec::with_capacity(self.records.len());
        for record in &self.records {
            let bundle_cid = record
                .bundle_cid
                .context("directory record missing bundle CID")?;
            let quorum_desc_cid = record
                .quorum_desc_cid
                .context("directory record missing quorum descriptor CID")?;
            entries.push(RecordSnapshotEntry {
                bundle_cid,
                quorum_desc_cid,
            });
        }
        let snapshot = DirectorySnapshot {
            version: DIRECTORY_SNAPSHOT_VERSION,
            records: entries,
            log: self.log.snapshot_metadata(),
        };
        self.log.store_snapshot(&snapshot)
    }

    pub fn export_car<W: Write>(&self, root: &Cid, writer: W) -> Result<()> {
        self.log
            .export_car(std::slice::from_ref(root), writer)
            .with_context(|| format!("failed to export CAR for root {root}"))
    }

    pub fn import_car<R: Read>(&mut self, reader: R) -> Result<Cid> {
        self.records.clear();
        self.log.reset();
        self.did_cache.clear();
        let roots = self.log.import_car(reader)?;
        let mut last_error: Option<Error> = None;
        for root in roots {
            match self.log.load_directory_snapshot(&root) {
                Ok(snapshot) => {
                    self.restore_from_snapshot(snapshot)?;
                    return Ok(root);
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow!("no directory snapshot root found")))
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    fn restore_from_snapshot(&mut self, snapshot: DirectorySnapshot) -> Result<()> {
        if snapshot.version != DIRECTORY_SNAPSHOT_VERSION {
            return Err(anyhow!(
                "unsupported directory snapshot version {}",
                snapshot.version
            ));
        }
        self.log.apply_snapshot(&snapshot.log);
        self.did_cache.clear();
        let mut records = Vec::with_capacity(snapshot.records.len());
        for entry in snapshot.records {
            let mut record: DirectoryRecord<K> =
                self.log.load_directory_record(&entry.bundle_cid)?;
            record.bundle_cid = Some(entry.bundle_cid);
            let quorum_cid = entry.quorum_desc_cid;
            let _: QuorumDescriptor = self.log.load_quorum_descriptor(&quorum_cid)?;
            record.quorum_desc_cid = Some(quorum_cid);
            records.push(record);
        }
        self.records = records;
        Ok(())
    }

    pub fn resolve_did_latest(&mut self, did: &Did) -> Result<Option<DirectoryRecord<K>>> {
        self.resolve_did_latest_at(did, Instant::now())
    }

    fn resolve_did_latest_at(
        &mut self,
        did: &Did,
        now: Instant,
    ) -> Result<Option<DirectoryRecord<K>>> {
        if let Some(entry) = self.did_cache.get(did).cloned() {
            if entry.is_valid(now) {
                let mut record = self.log.load_directory_record(&entry.cid)?;
                record.bundle_cid = Some(entry.cid);
                return Ok(Some(record));
            }
            self.did_cache.remove(did);
        }

        let Some(cid) = self.log.resolve_did_latest(did)? else {
            return Ok(None);
        };
        let mut record = self.log.load_directory_record(&cid)?;
        record.bundle_cid = Some(cid);
        self.did_cache
            .insert(did.clone(), DidCacheEntry::new(cid, now));
        Ok(Some(record))
    }
}

const DID_CACHE_TTL_SECS: u64 = 30;

#[derive(Clone, Debug)]
struct DidCacheEntry {
    cid: Cid,
    expires_at: Instant,
}

impl DidCacheEntry {
    fn new(cid: Cid, now: Instant) -> Self {
        Self {
            cid,
            expires_at: now + Duration::from_secs(DID_CACHE_TTL_SECS),
        }
    }

    fn is_valid(&self, now: Instant) -> bool {
        self.expires_at > now
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pin::PinReason;
    use crate::quorum::QuorumDescriptor;
    use crate::{generate_directory_record, record_fingerprint, MlKem1024};
    use std::fs::File;
    use std::time::{Duration, Instant};

    #[test]
    fn transparency_log_roundtrip() -> Result<()> {
        let quorum_desc = QuorumDescriptor {
            sig_algo: "BLS12381G1_XMD:SHA-256_SSWU_RO".to_string(),
            member_set_hash: [0u8; 32],
            epoch: 1,
        };
        let (rec, _) =
            generate_directory_record::<MlKem1024>(b"did:example".to_vec(), 1, quorum_desc)
                .unwrap();
        let mut dir = KeyDirectory::<MlKem1024>::new();
        let idx = dir.insert(rec.clone())?;
        let stored = dir.get(idx).expect("record present");
        assert!(stored.bundle_cid.is_some());
        assert!(stored.quorum_desc_cid.is_some());
        let root = dir.root();
        let proof = dir.prove(idx).unwrap();
        let leaf = record_fingerprint(&rec);
        assert!(proof.verify(leaf, root));
        let root_cid = dir.commit_root()?;
        let (committed_cid, committed_hash) =
            dir.last_committed_root().expect("root should be committed");
        assert_eq!(committed_cid, root_cid);
        assert_eq!(committed_hash, root);
        let node = dir.get_log_node(&root_cid)?;
        match node {
            LogNode::Leaf { fingerprint } => assert_eq!(fingerprint, leaf),
            LogNode::Branch { .. } | LogNode::Empty { .. } => {
                panic!("unexpected node type for single-leaf tree")
            }
        }
        Ok(())
    }

    #[test]
    fn commit_produces_branch_nodes() -> Result<()> {
        let mut log = TransparencyLog::new();
        let mut leaf_a = [0u8; 32];
        leaf_a[0] = 1;
        let mut leaf_b = [0u8; 32];
        leaf_b[0] = 2;
        let (_, cid_a) = log.put_leaf(leaf_a)?;
        let (_, cid_b) = log.put_leaf(leaf_b)?;
        let root_cid = log.commit_root()?;
        let node = log.get_node(&root_cid)?;
        match node {
            LogNode::Branch { left, right, hash } => {
                assert_eq!(left, cid_a);
                assert_eq!(right, cid_b);
                assert_eq!(hash, hash_pair(&leaf_a, &leaf_b));
            }
            LogNode::Leaf { .. } | LogNode::Empty { .. } => {
                panic!("expected branch node for two-leaf tree")
            }
        }
        Ok(())
    }

    #[test]
    fn fetch_latest_sth_empty() -> Result<()> {
        let log = TransparencyLog::new();
        assert!(log.fetch_latest_sth()?.is_none());
        Ok(())
    }

    #[test]
    fn publish_and_fetch_latest_sth() -> Result<()> {
        let mut log = TransparencyLog::new();
        let leaf = [42u8; 32];
        log.put_leaf(leaf)?;
        let root_cid = log.commit_root()?;
        let root_hash = log.root();
        let mut sth = SignedTreeHead {
            log_id: b"test-log".to_vec(),
            root_hash,
            tree_size: 1,
            sth_time: 10,
            root_cid,
            log_signature: vec![0xAA],
            witness_signatures: vec![vec![0xBB]],
        };
        let first_cid = log.publish_signed_tree_head(&sth)?;
        let fetched = log
            .fetch_latest_sth()?
            .expect("sth.latest should resolve after publish");
        assert_eq!(fetched, sth);

        sth.sth_time = 11;
        let second_cid = log.publish_signed_tree_head(&sth)?;
        assert_ne!(first_cid, second_cid);
        let fetched_updated = log
            .fetch_latest_sth()?
            .expect("sth.latest should resolve to updated STH");
        assert_eq!(fetched_updated, sth);
        Ok(())
    }

    #[test]
    fn pin_policy_tracks_sth_and_bundles() -> Result<()> {
        let quorum_desc = QuorumDescriptor {
            sig_algo: "BLS12381G1_XMD:SHA-256_SSWU_RO".to_string(),
            member_set_hash: [7u8; 32],
            epoch: 3,
        };
        let (record, _) =
            generate_directory_record::<MlKem1024>(b"did:pin".to_vec(), 5, quorum_desc.clone())
                .expect("record generation should succeed");
        let mut log = TransparencyLog::new();
        let fp = record_fingerprint(&record);
        let bundle_cid = log.store_directory_record(&record)?;
        let quorum_cid = log.store_quorum_descriptor(&quorum_desc)?;
        log.append(fp)?;

        let pin_records = log.pin_policy().pins();
        assert!(pin_records.iter().any(|entry| {
            entry.cid == bundle_cid && entry.reasons.contains(&PinReason::Bundle)
        }));
        assert!(pin_records.iter().any(|entry| {
            entry.cid == quorum_cid && entry.reasons.contains(&PinReason::Bundle)
        }));

        let root_cid = log.commit_root()?;
        let root_hash = log.root();
        let sth = SignedTreeHead {
            log_id: b"pin-log".to_vec(),
            root_hash,
            tree_size: 1,
            sth_time: 99,
            root_cid,
            log_signature: vec![0u8; 48],
            witness_signatures: Vec::new(),
        };
        log.publish_signed_tree_head(&sth)?;

        let policy = log.pin_policy();
        let (current_cid, current_size) =
            policy.current_sth().expect("current STH should be pinned");
        assert_eq!(*current_cid, root_cid);
        assert_eq!(current_size, 1);

        let has_current_reason = policy.pins().iter().any(|entry| {
            entry
                .reasons
                .iter()
                .any(|reason| matches!(reason, PinReason::CurrentSth { tree_size: 1 }))
        });
        assert!(has_current_reason);
        Ok(())
    }

    #[test]
    fn car_snapshot_round_trip() -> Result<()> {
        let quorum_desc = QuorumDescriptor {
            sig_algo: "BLS12381G1_XMD:SHA-256_SSWU_RO".to_string(),
            member_set_hash: [9u8; 32],
            epoch: 4,
        };
        let (record, _) =
            generate_directory_record::<MlKem1024>(b"did:car".to_vec(), 7, quorum_desc)
                .expect("record generation should succeed");
        let mut directory = KeyDirectory::<MlKem1024>::new();
        directory.insert(record.clone())?;
        let _root_cid = directory.commit_root()?;
        let snapshot_cid = directory.create_snapshot()?;

        let temp_dir = tempfile::tempdir()?;
        let car_path = temp_dir.path().join("snapshot.car");
        {
            let mut file = File::create(&car_path)?;
            directory.export_car(&snapshot_cid, &mut file)?;
        }

        let mut restored = KeyDirectory::<MlKem1024>::new();
        {
            let file = File::open(&car_path)?;
            let imported_root = restored.import_car(file)?;
            assert_eq!(imported_root, snapshot_cid);
        }

        assert_eq!(restored.record_count(), directory.record_count());
        assert_eq!(restored.root(), directory.root());
        let original = directory.get(0).expect("original record");
        let recovered = restored.get(0).expect("restored record");
        assert_eq!(recovered.did, original.did);
        assert_eq!(recovered.epoch, original.epoch);
        assert_eq!(recovered.kem_pk, original.kem_pk);
        assert_eq!(restored.pin_policy().pins(), directory.pin_policy().pins());
        Ok(())
    }

    #[test]
    fn publish_did_ipns_pointer() -> Result<()> {
        let quorum_desc = QuorumDescriptor {
            sig_algo: "BLS12381G1_XMD:SHA-256_SSWU_RO".to_string(),
            member_set_hash: [5u8; 32],
            epoch: 2,
        };
        let (record, _) =
            generate_directory_record::<MlKem1024>(b"did:ipns".to_vec(), 3, quorum_desc)
                .expect("record generation should succeed");
        let mut directory = KeyDirectory::<MlKem1024>::new();
        directory.insert(record.clone())?;

        let cid = directory
            .log
            .resolve_did_latest(&record.did)?
            .expect("ipns entry must exist");
        let loaded: DirectoryRecord<MlKem1024> = directory.log.load_directory_record(&cid)?;
        assert_eq!(loaded.did, record.did);
        Ok(())
    }

    #[test]
    fn resolve_did_latest_cache_hit() -> Result<()> {
        let quorum_desc = QuorumDescriptor {
            sig_algo: "BLS12381G1_XMD:SHA-256_SSWU_RO".to_string(),
            member_set_hash: [6u8; 32],
            epoch: 11,
        };
        let (record, _) =
            generate_directory_record::<MlKem1024>(b"did:cache".to_vec(), 8, quorum_desc)
                .expect("record generation should succeed");
        let mut directory = KeyDirectory::<MlKem1024>::new();
        directory.insert(record.clone())?;

        let did = record.did.clone();
        let first = directory
            .resolve_did_latest(&did)?
            .expect("cached record should resolve");
        assert_eq!(first.epoch, record.epoch);

        let key = std::str::from_utf8(&did).expect("valid did").to_string();
        directory.log.store.ipns_records.remove(&key);

        let cached = directory
            .resolve_did_latest(&did)?
            .expect("cache should provide record even without ipns");
        assert_eq!(cached.epoch, record.epoch);
        Ok(())
    }

    #[test]
    fn resolve_did_latest_cache_expiry() -> Result<()> {
        let quorum_desc = QuorumDescriptor {
            sig_algo: "BLS12381G1_XMD:SHA-256_SSWU_RO".to_string(),
            member_set_hash: [7u8; 32],
            epoch: 12,
        };
        let (record, _) =
            generate_directory_record::<MlKem1024>(b"did:expire".to_vec(), 9, quorum_desc)
                .expect("record generation should succeed");
        let mut directory = KeyDirectory::<MlKem1024>::new();
        directory.insert(record.clone())?;

        let did = record.did.clone();
        let entry = directory
            .did_cache
            .get_mut(&did)
            .expect("cache entry should exist after insert");
        entry.expires_at = Instant::now() - Duration::from_secs(60);

        let key = std::str::from_utf8(&did).expect("valid did").to_string();
        directory.log.store.ipns_records.remove(&key);

        assert!(directory.resolve_did_latest(&did)?.is_none());
        Ok(())
    }
}
