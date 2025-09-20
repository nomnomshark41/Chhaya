# AGENTS.md

## Scope
These guidelines apply to the entire repository unless a more specific `AGENTS.md` is added deeper in the tree.

## Project vision
Chhaya is a fully peer-to-peer, serverless secure-messaging protocol built with async Rust. All contributions must uphold the system goals:
- Preserve end-to-end security with AES-256-GCM, ML-KEM-1024, X25519, the Double Ratchet, VKD proofs, and BLS quorum co-signing.
- Maintain decentralization. Do **not** add central services, HTTP servers, or cloud-managed components.
- Respect privacy: sealed-sender envelopes, cover traffic, and zero plaintext metadata on the wire.

## Development rules
- Toolchain: Rust 2021 edition with Tokio for async. Enable `#![forbid(unsafe_code)]` unless a specific module already allows it.
- No panics, `unwrap`, or `expect` on untrusted input. Prefer `anyhow::Result` or typed errors via `thiserror`.
- Keep nonces deterministic (HKDF-n12), zeroize secrets, and use constant-time comparisons for sensitive data.
- Do not change cryptographic primitives or message flows without prior agreement.
- Logging must omit secrets; use `info!` for state changes and `warn!` when verification fails.

## Architecture expectations
- Extend existing modules (`p2p`, `vkd`, `logstore`, `integrations`, `directory`, `quorum`, `safety`) instead of creating redundant structures.
- Public APIs should stay small, documented with `///`, and avoid global mutable state.
- Directory data is untrusted transport. Accept updates only after `verify_vkd_proof` validates signatures, witness thresholds, inclusion, optional consistency, and VRF.

## Code quality
- Ensure reproducible builds with pinned dependencies. Do not introduce unchecked optional features.
- Maintain `clippy::pedantic` cleanliness and treat compiler warnings as errors (`RUSTFLAGS="-D warnings"`).
- Zeroize secrets on drop and prefer constant-time comparisons where relevant.

## Testing & verification
Before opening a PR or concluding work:
1. `cargo fmt --all`
2. `cargo clippy --all-targets --all-features -- -D warnings`
3. `cargo test --all`
4. Run property tests (`cargo test --all -- --ignored` or module-specific proptests) when modified.
5. Execute fuzz harnesses with `cargo fuzz run <target>` for any touched fuzz target.
6. Keep Known Answer Tests (KATs) up to date.
7. Audit dependencies with `cargo deny check` and `cargo audit` when the lockfile changes.

Document any deviations or skipped checks in commit messages or PR descriptions.

## Documentation
- Update `docs/` and module-level comments when behavior changes.
- Explain design decisions and threat-model implications in Markdown docs.

## Security posture
- Treat all inbound network and directory data as adversarial.
- Prefer defensive parsing and validation patterns over assertions.
- Never log secrets or long-term keys.

Stay aligned with these guidelines so future AI agents and humans can contribute safely and consistently.
