// This file is part of Chhaya and is licensed under the GNU Affero General Public License v3.0 or later.
// See the LICENSE file in the project root for license details.

#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, ensure, Context, Result};
use blstrs::Scalar;
use chhaya::p2p::bootstrap::{
    scalar_from_hex, scalar_to_hex, signature_to_hex, BootstrapList, BootstrapPeerRecord,
    BootstrapSignature, QuorumConfig, SignedBootstrapList,
};
use chhaya::quorum::{aggregate_signatures, bls_sign, SIG_DST};
use clap::{Parser, Subcommand};
use ff::PrimeField;
use libp2p::{Multiaddr, PeerId};
use serde::Deserialize;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "bootstrap-tool",
    about = "Create and sign bootstrap peer lists"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Create(CreateArgs),
    Sign(SignArgs),
}

#[derive(Parser)]
struct CreateArgs {
    #[arg(long)]
    out: PathBuf,
    #[arg(long)]
    expires: u64,
    #[arg(long)]
    published: Option<u64>,
    #[arg(long, default_value_t = 1)]
    version: u32,
    #[arg(long = "peer", value_parser = parse_peer_entry)]
    peers: Vec<PeerEntry>,
}

#[derive(Parser)]
struct SignArgs {
    #[arg(long)]
    list: PathBuf,
    #[arg(long)]
    quorum: PathBuf,
    #[arg(long)]
    out: PathBuf,
    #[arg(long = "share")]
    shares: Vec<PathBuf>,
}

#[derive(Clone, Debug)]
struct PeerEntry {
    peer_id: String,
    addresses: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ShareFile {
    id: String,
    secret: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Create(args) => handle_create(args),
        Command::Sign(args) => handle_sign(args),
    }
}

fn handle_create(args: CreateArgs) -> Result<()> {
    ensure!(
        !args.peers.is_empty(),
        "at least one --peer entry is required"
    );
    let published = args.published.unwrap_or(current_unix_time()?);
    ensure!(
        args.expires > published,
        "expiration must be greater than publication timestamp"
    );

    let mut peers = Vec::with_capacity(args.peers.len());
    for entry in args.peers {
        let _ = PeerId::from_str(&entry.peer_id)
            .map_err(|_| anyhow!("invalid peer id: {}", entry.peer_id))?;
        let mut addresses = Vec::with_capacity(entry.addresses.len());
        for addr in entry.addresses {
            let _ = Multiaddr::from_str(&addr)
                .map_err(|_| anyhow!("invalid multiaddr {addr} for peer {}", entry.peer_id))?;
            addresses.push(addr);
        }
        peers.push(BootstrapPeerRecord {
            peer_id: entry.peer_id,
            addresses,
        });
    }

    let mut list = BootstrapList {
        version: args.version,
        published_at: published,
        expires_at: args.expires,
        peers,
    };
    list.canonicalize();

    let data = serde_json::to_vec_pretty(&list).context("serialise bootstrap list")?;
    fs::write(&args.out, data)
        .with_context(|| format!("failed to write {}", args.out.display()))?;
    Ok(())
}

fn handle_sign(args: SignArgs) -> Result<()> {
    ensure!(
        !args.shares.is_empty(),
        "at least one --share must be supplied"
    );
    let list_bytes =
        fs::read(&args.list).with_context(|| format!("failed to read {}", args.list.display()))?;
    let mut list: BootstrapList = serde_json::from_slice(&list_bytes)
        .with_context(|| format!("failed to parse {}", args.list.display()))?;
    list.canonicalize();

    let quorum_bytes = fs::read(&args.quorum)
        .with_context(|| format!("failed to read {}", args.quorum.display()))?;
    let quorum_cfg: QuorumConfig = serde_json::from_slice(&quorum_bytes)
        .with_context(|| format!("failed to parse {}", args.quorum.display()))?;
    let quorum = quorum_cfg.into_trusted()?;

    let message = quorum.signing_message(&list)?;
    let mut parts = Vec::new();
    let mut signers = Vec::new();
    let mut seen = HashSet::new();

    for path in &args.shares {
        let data = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
        let share: ShareFile = serde_json::from_slice(&data)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        let id = scalar_from_hex(&share.id)?;
        let id_hex = scalar_to_hex(&id);
        if !seen.insert(id_hex.clone()) {
            bail!("duplicate share identifier provided: {id_hex}");
        }
        let secret = parse_secret_scalar(&share.secret)?;
        let sig = bls_sign(&secret, &message, SIG_DST);
        parts.push((id, sig));
        signers.push(id_hex);
    }

    ensure!(
        parts.len() >= quorum.minimum_signers,
        "insufficient shares provided: need {}",
        quorum.minimum_signers
    );
    let aggregated = aggregate_signatures(&parts)
        .map_err(|error| anyhow!("failed to aggregate signatures: {error:?}"))?;

    let signed = SignedBootstrapList {
        quorum: quorum.descriptor.clone(),
        list,
        signature: BootstrapSignature {
            aggregated: signature_to_hex(&aggregated),
            signers,
        },
    };

    let data = serde_json::to_vec_pretty(&signed).context("serialise signed list")?;
    fs::write(&args.out, data)
        .with_context(|| format!("failed to write {}", args.out.display()))?;
    Ok(())
}

fn parse_peer_entry(value: &str) -> Result<PeerEntry, String> {
    let (peer, addresses) = value
        .split_once('=')
        .ok_or_else(|| "expected <peer_id>=<addr1>,<addr2>".to_string())?;
    let peer = peer.trim();
    if peer.is_empty() {
        return Err("peer id cannot be empty".to_string());
    }
    let mut addrs = Vec::new();
    for addr in addresses.split(',') {
        let trimmed = addr.trim();
        if trimmed.is_empty() {
            return Err("empty multiaddr entry".to_string());
        }
        addrs.push(trimmed.to_string());
    }
    Ok(PeerEntry {
        peer_id: peer.to_string(),
        addresses: addrs,
    })
}

fn current_unix_time() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| anyhow!("current time is before the unix epoch"))?
        .as_secs())
}

fn parse_secret_scalar(hex_value: &str) -> Result<Scalar> {
    let decoded = Zeroizing::new(
        hex::decode(hex_value).map_err(|_| anyhow!("invalid secret scalar encoding"))?,
    );
    if decoded.len() != 32 {
        bail!("secret scalar must be 32 bytes");
    }
    let mut buf = Zeroizing::new([0u8; 32]);
    buf.copy_from_slice(&decoded);
    Scalar::from_repr(*buf)
        .into_option()
        .ok_or_else(|| anyhow!("secret scalar not in field"))
}
