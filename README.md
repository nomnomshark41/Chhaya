# Chhaya

[![Rust](https://github.com/nomnomshark41/Chhaya/actions/workflows/rust.yml/badge.svg)](https://github.com/nomnomshark41/Chhaya/actions/workflows/rust.yml)

Chhaya is a fully peer-to-peer, serverless secure-messaging protocol written in async Rust. The project combines battle-tested
cryptography with modern peer-discovery and transport primitives to deliver verifiable confidentiality, integrity, and
availability without any central authority.

## Table of contents

- [Features](#features)
- [Architecture highlights](#architecture-highlights)
- [Getting started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Build](#build)
  - [Tests](#tests)
  - [Fuzzing](#fuzzing)
  - [Audits & dependency hygiene](#audits--dependency-hygiene)
- [Development philosophy](#development-philosophy)
- [Security & privacy model](#security--privacy-model)
- [Project status](#project-status)
- [Additional resources](#additional-resources)

## Features

- **Pure peer-to-peer networking** powered by `libp2p` (QUIC transport with Noise handshakes, Kademlia DHT, gossipsub,
  autonat, relay v2, and mDNS) – there are no central servers or trusted relays.
- **End-to-end cryptography** with AES-256-GCM for symmetric confidentiality, ML-KEM-1024 and X25519 for key exchange,
  Double Ratchet for forward secrecy, and deterministic HKDF-n12 nonce derivation.
- **Verifiable key transparency** via VKD/CONIKS-style proofs, cross-checked with BLS quorum co-signatures to prevent
  equivocation.
- **Hardened secret management**: secrets are zeroized on drop, constant-time comparisons avoid timing channels, and
  sealed-sender envelopes hide metadata.
- **Modular design** aligned with security boundaries: the core modules live in `p2p`, `vkd`, `logstore`, `integrations`,
  `directory`, `quorum`, and `safety` so functionality stays composable and testable.

## Architecture highlights

Chhaya is split into a handful of focused crates/modules to make auditing and testing straightforward:

- `p2p`: swarm orchestration, DHT management, gossip propagation, and transport negotiation.
- `vkd`: producers, fetchers, and caches for verifiable key-directory data; all directory responses are treated as
  untrusted until `verify_vkd_proof` succeeds.
- `logstore`: append-only storage for ratchets, signatures, and delivery receipts.
- `integrations`: adapters such as the `handshake_resolver` for bridging network identities to VKD commitments.
- `directory`: helpers for processing transparency proofs and handling cover-traffic envelopes.
- `quorum`: BLS-based signature aggregation and threshold validation.
- `safety`: shared invariants, zeroization helpers, and constant-time comparison utilities.

See [`docs/`](docs/) for deeper architectural notes, design rationales, and threat-model discussions as they evolve.

## Getting started

### Prerequisites

- Rust 1.74+ with the 2021 edition toolchain installed via [`rustup`](https://rustup.rs/)
- `cargo` and `rustfmt` (installed automatically with the toolchain)
- Recommended: [`cargo-nextest`](https://nexte.st/) for faster test iterations and [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz)

### Build

```bash
cargo build
```

Chhaya forbids `unsafe` code by default and builds with `RUSTFLAGS="-D warnings"`, so treating compiler diagnostics as
non-negotiable keeps the binary reproducible and reviewable.

### Tests

Run the full suite before opening a pull request or landing changes:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
# Property tests (may take longer; run with --ignored if applicable)
cargo test --all -- --ignored
```

### Fuzzing

The repository ships with [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) targets under [`fuzz/`](fuzz/). Execute
any touched fuzz targets locally to guard against parser or protocol regressions:

```bash
cargo fuzz run <target>
```

### Audits & dependency hygiene

When `Cargo.lock` changes, verify the dependency graph:

```bash
cargo deny check
cargo audit
```

## Development philosophy

- Preserve end-to-end security guarantees—do not weaken cryptographic flows or nonce derivations.
- All network or directory inputs are adversarial until proven otherwise: prefer explicit validation over `unwrap` or
  `expect` and return `anyhow::Result` or typed errors.
- Keep public APIs minimal, documented, and async-friendly (`tokio`). Avoid global mutable state.
- Log only high-level state transitions at `info!` and potential verification issues at `warn!`; never log secrets.

## Security & privacy model

Chhaya assumes that transport layers, directories, and peers may be malicious. Critical protections include:

- Verifying VKD proofs (log signatures, witness thresholds, inclusion, optional consistency, and VRFs) before accepting
  directory data.
- Sealed-sender envelopes and cover traffic to hide sender identity and metadata on the wire.
- Deterministic nonce derivation with HKDF-n12 paired with AES-256-GCM to prevent reuse and nonce-malleability.
- Zeroization and constant-time primitives to limit side channels and key retention.

If you discover a vulnerability, please contact the maintainers privately before filing an issue.

## Project status

Chhaya is under active development; expect APIs, protocols, and tooling to evolve. Contributions that align with the
security-first, decentralized vision are welcome. Open issues tagged `good-first-issue` or `help-wanted` are great entry
points for new contributors.

## Additional resources

- [`docs/wire-spec.md`](docs/wire-spec.md) for a deeper breakdown of subsystems and flows
- [`docs/threat-model.md`](docs/threat-model.md) for attacker assumptions and mitigations
- [`LICENSE`](LICENSE) for licensing information

