# HOWTOUSE

This guide walks through compiling the tooling, running a Chhaya peer, and operating the supporting utilities that keep the network verifiable and decentralised.

## 1. Build the binaries

1. Install the Rust 2021 toolchain (Rust 1.74 or newer) with `rustup`, which pulls in `cargo`, `rustfmt`, and `clippy` automatically.
2. Compile everything in release mode to produce the peer utilities:
   ```bash
   cargo build --release
   ```
   Binaries land in `target/release/chhaya` and `target/release/bootstrap-tool`.
3. Optionally install them into your local `cargo` bin directory:
   ```bash
   cargo install --path . --bins
   ```
   Both crates forbid `unsafe` code and build with `RUSTFLAGS="-D warnings"`, so fix every compiler or linter diagnostic before trusting the output.

## 2. Start a peer inside your application

Chhaya is a library-first project; you embed the swarm directly in your process. The minimal steps are:

1. Load and verify a signed VKD config to obtain `VkdTrustAnchors`.
2. Build a `P2pConfig` with listening addresses, bootstrap material, and the trust anchors.
3. Spawn the async `P2pNode` to join the network, then interact with gossip, request/response exchanges, and DHT helpers as needed.

```rust
use anyhow::{anyhow, Context, Result};
use blstrs::{G2Affine, G2Projective};
use chhaya::p2p::{bootstrap::BootstrapSource, P2pConfig, P2pNode};
use chhaya::vkd::{SignedVkdConfig, VkdTrustAnchors};
use tokio::signal;

fn decode_g2(hex: &str) -> Result<G2Projective> {
    let bytes = hex::decode(hex).context("invalid G2 encoding")?;
    if bytes.len() != 96 {
        return Err(anyhow!("unexpected compressed size"));
    }
    let mut buf = [0u8; 96];
    buf.copy_from_slice(&bytes);
    let affine = G2Affine::from_compressed(&buf)
        .into_option()
        .ok_or_else(|| anyhow!("point not on curve"))?;
    Ok(G2Projective::from(&affine))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    // 1. Load and verify the VKD trust anchors.
    let signer_pk = decode_g2(&std::env::var("CHHAYA_VKD_SIGNER_PK")?)?;
    let raw = tokio::fs::read("config/vkd-trust.json").await?;
    let signed: SignedVkdConfig = serde_json::from_slice(&raw)?;
    let anchors: std::sync::Arc<VkdTrustAnchors> =
        std::sync::Arc::new(signed.verify(&signer_pk)?);

    // 2. Configure the swarm.
    let mut config = P2pConfig::default();
    config.vkd_trust = Some(std::sync::Arc::clone(&anchors));
    config.bootstrap_sources.push(BootstrapSource::from("bootstrap.json".into()));
    config.gossip_validation = libp2p::gossipsub::ValidationMode::Strict;

    // 3. Run the node until interrupted.
    let node = P2pNode::run(config).await?;
    let mut sth_events = node.subscribe("/vkd/sth/v1").await?;

    loop {
        tokio::select! {
            Ok(msg) = sth_events.recv() => {
                let announcement: chhaya::vkd::SthAnnouncement = serde_cbor::from_slice(&msg.data)?;
                chhaya::vkd::verify_sth_announcement(&announcement, anchors.as_ref())?;
                // Handle the new STH (e.g. fetch proofs and call verify_vkd_proof).
            }
            _ = signal::ctrl_c() => {
                break;
            }
        }
    }

    node.stop().await?;
    Ok(())
}
```

Key interactions exposed by `P2pNode` include publishing gossip, subscribing to topics, advertising rendezvous records, putting/getting DHT values, and driving request/response exchanges for sealed-sender deliveries. Always verify gossip payloads such as VKD STH announcements before acting on them using `verify_sth_announcement`.

## 3. Manage the verifiable key directory

The `KeyDirectory` type encapsulates the append-only transparency log, CAR snapshotting, and DID cache. Typical workflows:

- Import a signed snapshot:
  ```rust
  let mut directory = chhaya::directory::KeyDirectory::<chhaya::MlKem1024>::new();
  let root = directory.import_car(std::fs::File::open("directory.car")?)?;
  println!("loaded snapshot {root} with {} records", directory.record_count());
  ```
- Resolve the latest entry for a DID, with automatic IPNS lookups and cache refreshes.
- Export a CAR for replication or backups after applying new verified records.

When applying fresh VKD updates from the network, accept them only if `verify_vkd_proof` succeeds against your trusted anchors (log signature, witness threshold, inclusion, optional consistency checks, and VRF commitments). Persist accepted bundles using `ProofQueue` to deduplicate and audit replayed proofs.

## 4. Use the `chhaya` CLI for local maintenance

The `chhaya` binary exposes two helper command families: pin policy inspection and CAR import/export. Examples:

- Show which bundles are currently pinned:
  ```bash
  cargo run --bin chhaya -- pin ls --store pins.json
  ```
- Prune historical checkpoints but keep a sliding window of recent ones:
  ```bash
  cargo run --bin chhaya -- pin prune --keep 5
  ```
- Export a verifiable snapshot around a specific CID:
  ```bash
  chhaya car export bafyreia... --out snapshot.car --store directory.car
  ```
- Import a CAR snapshot into your local store (directories are created automatically):
  ```bash
  chhaya car import snapshot.car --store directory.car
  ```

These commands rely on the same `PinPolicy` and `KeyDirectory` implementations used by the library, so they never bypass verification logic.

## 5. Publish bootstrap lists with `bootstrap-tool`

Peers rely on signed bootstrap lists backed by a BLS quorum. The `bootstrap-tool` binary lets you create and co-sign those bundles.

1. Create an unsigned list from trusted peer IDs and multiaddrs:
   ```bash
   bootstrap-tool create \
     --out unsigned.json \
     --expires $(($(date +%s) + 604800)) \
     --peer 12D3KooW...=/ip4/198.51.100.10/udp/4001/quic-v1 \
     --peer 12D3KooX...=/dns4/example.org/udp/4001/quic-v1
   ```
2. Collect threshold shares, sign, and aggregate the BLS signature:
   ```bash
   bootstrap-tool sign \
     --list unsigned.json \
     --quorum quorum.json \
     --out signed.json \
     --share shares/operator-1.json \
     --share shares/operator-5.json
   ```
3. Distribute `signed.json` to operators. Consumers load it through `P2pConfig::bootstrap_sources`, which verifies expiry, quorum descriptors, allowed signers, and aggregated signatures before dialling peers.

## 6. Operational checklist before deploying changes

Always run the full verification suite before publishing a release or opening a pull request:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
cargo test --all -- --ignored
# Run cargo fuzz for any fuzz target you touched
```

If you update `Cargo.lock`, also run `cargo deny check` and `cargo audit` to keep dependencies pinned and vulnerability-free.

Sticking to these steps preserves the protocol’s end-to-end security guarantees while keeping the tooling reproducible and trustworthy.
