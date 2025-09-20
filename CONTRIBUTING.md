# Contributing to Chhaya

Chhaya exists to prove that secure, metadata-resistant messaging does not require central servers. Every change must
strengthen the peer-to-peer, security-first design. This guide summarizes how to collaborate effectively, keep the
protocol trustworthy, and ship high-quality Rust code.

## Code of Conduct

Participation in Chhaya is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). Be respectful, inclusive, and mindful of
the diverse backgrounds of collaborators. If you witness or experience a violation, contact the maintainers immediately.

## How we work

- **Decentralization is non-negotiable.** No central services, HTTP control planes, or cloud-managed components may be
  introduced. The network is fully peer-to-peer over `libp2p` (QUIC + Noise, Kademlia DHT, gossipsub, autonat, relay v2,
  and mDNS).
- **Security comes first.** Preserve the existing cryptographic flows: AES-256-GCM, ML-KEM-1024, X25519, the Double
  Ratchet, deterministic HKDF-n12 nonces, sealed-sender envelopes, cover traffic, VKD proofs, and BLS quorum co-signing.
  Do not swap primitives or weaken checks without an accepted design discussion.
- **Zero trust for inbound data.** Treat all directory and network inputs as adversarial. Accept directory updates only
  after `verify_vkd_proof` validates log signatures, witness thresholds, inclusion, optional consistency, and VRF outputs.
- **Async Rust everywhere.** Use Rust 2021 with Tokio; avoid blocking I/O in async contexts. Public APIs should be small,
  `Send`/`Sync` where necessary, and return `anyhow::Result` or typed `thiserror` errors.
- **Memory safety matters.** Crates should keep `#![forbid(unsafe_code)]` unless there is an explicit, reviewed exception.
  Zeroize secrets, use constant-time comparisons, and never log sensitive material.

## Getting started

1. **Find or open an issue.** Start with issues tagged `good-first-issue` or `help-wanted`, or open a new issue/RFC to
   discuss substantial work.
2. **Sync with maintainers.** Significant protocol, cryptography, or transport changes require design agreement before
   implementation.
3. **Set up tooling.**
   - Install Rust 1.74+ via [`rustup`](https://rustup.rs/) with `cargo`, `rustfmt`, and `clippy`.
   - Add [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz), [`cargo-nextest`](https://nexte.st/), and
     [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny) for faster validation.
   - Configure `RUSTFLAGS="-D warnings"` to keep builds reproducible and fail on warnings.
4. **Clone and branch.** Use a topic branch in your fork (e.g., `feature/vkd-proof-cache`) so reviews stay focused.

### Repository map

The major crates/modules align with security boundaries:

- `p2p`: swarm orchestration, transport negotiation, DHT, gossip, relay, autonat, and peer discovery.
- `vkd`: producers, fetchers, caches, and verification helpers for transparency proofs.
- `logstore`: append-only persistence for ratchets, signatures, and delivery receipts.
- `integrations`: adapters (e.g., `handshake_resolver`) that map peer identities to VKD commitments.
- `directory`: parsing and validation for transparency data and sealed envelopes.
- `quorum`: BLS aggregation, witness tracking, and threshold enforcement.
- `safety`: shared invariants, zeroization utilities, and constant-time helpers.

Prefer extending these modules over adding parallel abstractions.

## Development guidelines

### Architecture & design

- Keep public APIs narrow, well-documented (`///`), and explicit about async expectations.
- Avoid global mutable state; prefer dependency injection and typed configuration.
- Feature flags should remain deterministic and documented. Do not introduce optional crypto/security behavior by default.

### Security & privacy expectations

- Never panic on untrusted input. Replace `unwrap`/`expect` with explicit error handling.
- Maintain deterministic HKDF-n12 nonce derivation and reuse prevention.
- Preserve sealed-sender semantics and cover-traffic scheduling; document any tuning of padding or delays.
- Do not log secrets, private keys, ratchet states, or identifiers that could deanonymize peers.

### Error handling & logging

- Return `anyhow::Result` for application-level fallibility or define precise error enums using `thiserror`.
- Use `info!` for state transitions, `warn!` for verification failures, and `trace!`/`debug!` only when they cannot leak
  secrets.
- Prefer `tracing` spans for complex async flows to simplify debugging without exposing sensitive payloads.

### Testing & verification hooks

- Place unit and property tests alongside the modules they exercise. Favor `proptest` for invariants and HKDF/KEM KATs
  for crypto boundaries.
- Keep fuzz targets in `fuzz/` narrowly scoped and deterministic; update KAT fixtures when protocol constants change.

### Documentation

- Update `docs/` and relevant README sections whenever behavior, threat models, or network interactions shift.
- Explain architectural decisions, trade-offs, and impacts on verification or privacy.

## Required checks before opening a pull request

Run the full pipeline locally and include the results in your pull request description:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
# Property tests (mark long-running ones with #[ignore])
cargo test --all -- --ignored
# Fuzz any touched targets
cargo fuzz run <target>
# Dependency audits (only when Cargo.lock changes)
cargo deny check
cargo audit
```

Document any skipped checks (e.g., due to platform constraints) and justify them. Contributions that fail these steps will
not be merged.

## Commit & pull request expectations

- Write commits in the imperative mood (e.g., "Add sealed-sender cover traffic sampler"). Keep them focused and
  rebased on the latest `main`.
- Reference the related issue or RFC in your pull request and summarize the security/privacy impact.
- Include a testing section in the pull request body that lists the commands executed and their results.
- Reviewers will expect thorough explanations of cryptographic or protocol changes; be ready to link to specs, papers, or
  internal docs.

## Reporting vulnerabilities

If you find a security issue, do **not** open a public issue. Contact the maintainers privately with enough detail to
reproduce the problem. We will coordinate a fix, tests, and a disclosure process.

## Thank you

Your contributions keep Chhaya trustworthy, private, and resilient. We appreciate the time you spend hardening the stack
and helping peers communicate safely without central authorities.
