# Pull Request Template

## Summary
- [ ] Explain the protocol- or security-relevant changes and why they are needed.
- [ ] Note any impacts to decentralization, privacy guarantees, or cryptographic flows.

## Testing & Verification
Check all commands that were executed locally for this change:
- [ ] `cargo fmt --all`
- [ ] `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] `cargo test --all`
- [ ] Property tests (`cargo test --all -- --ignored` or module-specific)
- [ ] `cargo fuzz run <target>` (if a touched fuzz target exists)
- [ ] `cargo deny check`
- [ ] `cargo audit`

## Security Review
- [ ] Deterministic nonces (HKDF-n12) preserved where applicable.
- [ ] Secrets are zeroized or otherwise cleared on drop.
- [ ] No new panics or `unwrap`/`expect` on untrusted input.
- [ ] No plaintext metadata is introduced on the wire; sealed-sender envelope integrity maintained.
- [ ] Directory updates still require `verify_vkd_proof` success prior to acceptance.

## Additional Notes
Add context that reviewers or operators should know, including protocol diagrams, threat-model implications, or follow-up tasks.
