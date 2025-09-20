# Threat Model

This document summarizes the protection goals, scoped non-goals, and adversary assumptions for the Chhaya protocol implementation. It links each relevant threat to the mitigations currently embodied in the wire format and highlights residual risk that remains after those controls.

## Security Goals

* **Authenticated directory bindings.** Peers should only accept directory material that is signed by the quorum and provably consistent with the verifiable key directory (VKD), preventing malicious key substitution. [Handshake overview](./wire-spec.md#handshake-overview) [M1 HandshakeInit](./wire-spec.md#m1-handshakeinit)
* **Confidential, forward-secure transport.** Session establishment and subsequent Double Ratchet transport must preserve message confidentiality, integrity, and post-compromise security using the hybrid handshake and deterministic nonce discipline. [Handshake overview](./wire-spec.md#handshake-overview) [Deterministic nonce derivation](./wire-spec.md#deterministic-nonce-derivation) [Double Ratchet transport](./wire-spec.md#double-ratchet-transport)
* **Metadata minimization.** Observers should learn as little as practical about communicating parties through sealed-sender envelopes and padding conventions. [M1 HandshakeInit](./wire-spec.md#m1-handshakeinit) [Sealed-sender envelope](./wire-spec.md#sealed-sender-envelope-v1)
* **Replay resistance.** Handshakes and Double Ratchet messages should be single-use, rejecting replayed ciphertexts and transcript replays. [State machine verification](./wire-spec.md#state-machine-transitions-and-verification) [Deterministic nonce derivation](./wire-spec.md#deterministic-nonce-derivation)
* **Resource-bound admission control.** Attackers must solve stateless puzzles before compelling expensive private-key operations, keeping denial-of-service within manageable bounds. [Retry cookie format](./wire-spec.md#retry-cookie-binary-format) [State machine verification](./wire-spec.md#state-machine-transitions-and-verification)

## Non-Goals

* **Endpoint compromise.** The protocol does not attempt to secure devices that are already compromised or leaking secrets via side channels.
* **Perfect anonymity against global observers.** Cover traffic and sealed-sender envelopes reduce metadata leakage but do not guarantee full unlinkability against adversaries monitoring all links.
* **Network-layer availability.** Attacks that entirely partition the underlying transport (e.g., routing black holes) are out of scope.

## Adversary Scenarios & Mitigations

### Nation-state adversary

* **Capabilities.** Extensive compute resources, global passive collection, and control over subsets of network infrastructure.
* **Mitigations.**
  * VKD proofs and quorum-signed spend receipts prevent key-directory tampering even if the directory transport is malicious. [State machine verification](./wire-spec.md#state-machine-transitions-and-verification) [M1 HandshakeInit](./wire-spec.md#m1-handshakeinit)
  * Hybrid X25519 + ML-KEM handshake with deterministic nonces enforces transcript integrity and resists downgrade or key-reuse attacks. [Handshake overview](./wire-spec.md#handshake-overview) [Deterministic nonce derivation](./wire-spec.md#deterministic-nonce-derivation)
  * Double Ratchet transport maintains forward secrecy after compromise, limiting the value of captured ciphertext. [Double Ratchet transport](./wire-spec.md#double-ratchet-transport)
* **Residual risk.** Compromise of quorum keys or a majority of VKD witnesses would undermine authenticity guarantees; the protocol assumes these roots of trust stay honest.

### Sybil / Eclipse adversary

* **Capabilities.** Floods the peer-to-peer overlay with identities and attempts to isolate honest nodes.
* **Mitigations.**
  * Spend receipts must carry BLS quorum signatures for each identity, throttling mass registration and providing verifiable membership. [M1 HandshakeInit](./wire-spec.md#m1-handshakeinit) [State machine verification](./wire-spec.md#state-machine-transitions-and-verification)
  * Retry cookies embed proof-of-work puzzles so responders can force attackers to expend resources before engaging in expensive state transitions. [Retry cookie format](./wire-spec.md#retry-cookie-binary-format) [State machine verification](./wire-spec.md#state-machine-transitions-and-verification)
  * VKD inclusion proofs bind directory epochs, making it difficult for eclipsed nodes to accept forged key material. [State machine verification](./wire-spec.md#state-machine-transitions-and-verification)
* **Residual risk.** The protocol cannot stop an adversary from occupying large portions of the DHT if the underlying libp2p routing lacks additional Sybil defenses; higher-layer peer selection remains necessary.

### Replay adversary

* **Capabilities.** Captures legitimate handshake or transport ciphertexts and replays them to peers to desynchronize state or impersonate participants.
* **Mitigations.**
  * Responders derive session identifiers from the transcript bind and maintain a replay cache, rejecting duplicate handshakes. [State machine verification](./wire-spec.md#state-machine-transitions-and-verification)
  * Deterministic nonce derivation ties AEAD nonces to unique handshake hashes and message keys, making nonce reuse detectable and blocking ciphertext replays. [Deterministic nonce derivation](./wire-spec.md#deterministic-nonce-derivation)
  * Double Ratchet counters enforce monotonically increasing message numbers with strict ceilings. [Double Ratchet transport](./wire-spec.md#double-ratchet-transport)
* **Residual risk.** Replay protection depends on correct cache management and synchronized ratchet state; state loss or rollback on a device could reopen replay windows until recovery completes.

### Deanonymization adversary

* **Capabilities.** Attempts to link ciphertexts to senders or receivers by inspecting payload structure or directory metadata.
* **Mitigations.**
  * Sealed-sender envelopes hide sender identifiers inside the Double Ratchet ciphertext, removing plaintext metadata. [Sealed-sender envelope](./wire-spec.md#sealed-sender-envelope-v1)
  * Handshake padding options obscure DID lengths and batch sizes, complicating straightforward identification. [M1 HandshakeInit](./wire-spec.md#m1-handshakeinit) [Handshake overview](./wire-spec.md#handshake-overview)
* **Residual risk.** Traffic correlation across multiple network vantage points can still deanonymize users if timing patterns are distinctive or if cover traffic is not sustained.

### Traffic analysis adversary

* **Capabilities.** Observes packet sizes, timing, and frequency to infer relationships or message content.
* **Mitigations.**
  * Cover padding on handshake and Double Ratchet payloads allows peers to equalize message sizes across configurable buckets. [M1 HandshakeInit](./wire-spec.md#m1-handshakeinit) [Double Ratchet transport](./wire-spec.md#double-ratchet-transport)
  * Deterministic, transcript-bound AEAD nonces prevent adversaries from inferring state via nonce randomness variations. [Deterministic nonce derivation](./wire-spec.md#deterministic-nonce-derivation)
  * Constant AAD structure for Double Ratchet ciphertexts avoids leaking extra metadata in headers. [Double Ratchet transport](./wire-spec.md#double-ratchet-transport)
* **Residual risk.** Size buckets and timing padding cannot fully conceal high-volume conversations; sophisticated analysts may still extract communication graphs from flow metadata.

### Denial of Service adversary

* **Capabilities.** Tries to exhaust CPU, memory, or bandwidth by initiating numerous handshakes or sending malformed traffic.
* **Mitigations.**
  * Retry cookies with embedded puzzles allow responders to ratchet up difficulty before committing to expensive ML-KEM decapsulation. [Retry cookie format](./wire-spec.md#retry-cookie-binary-format) [State machine verification](./wire-spec.md#state-machine-transitions-and-verification)
  * Transcript validation and bind checks precede secret derivation, cheaply filtering malformed inputs. [Handshake overview](./wire-spec.md#handshake-overview) [State machine verification](./wire-spec.md#state-machine-transitions-and-verification)
  * Double Ratchet message counters enforce bounds and reject out-of-window ciphertexts. [Double Ratchet transport](./wire-spec.md#double-ratchet-transport)
* **Residual risk.** Puzzles raise the cost for attackers but also impact low-power legitimate clients; extreme distributed DoS can still saturate network links faster than puzzles can throttle.

## Risk Summary

| Threat | Severity | Likelihood | Primary Mitigations | Residual Risk |
| --- | --- | --- | --- | --- |
| Nation-state compromise | High | Medium | VKD proofs, quorum-signed receipts, hybrid handshake, deterministic nonces, Double Ratchet. [Handshake overview](./wire-spec.md#handshake-overview) [State machine verification](./wire-spec.md#state-machine-transitions-and-verification) [Deterministic nonce derivation](./wire-spec.md#deterministic-nonce-derivation) [Double Ratchet transport](./wire-spec.md#double-ratchet-transport) | Catastrophic if quorum keys or VKD witnesses fall; assumes honest majority.
| Sybil / Eclipse | Medium | Medium | BLS quorum receipts, VKD inclusion proofs, retry-cookie puzzles. [M1 HandshakeInit](./wire-spec.md#m1-handshakeinit) [State machine verification](./wire-spec.md#state-machine-transitions-and-verification) [Retry cookie format](./wire-spec.md#retry-cookie-binary-format) | Underlying peer selection can still be saturated without complementary overlay defenses.
| Replay | Medium | Low | Transcript bind replay cache, deterministic nonces, Double Ratchet counters. [State machine verification](./wire-spec.md#state-machine-transitions-and-verification) [Deterministic nonce derivation](./wire-spec.md#deterministic-nonce-derivation) [Double Ratchet transport](./wire-spec.md#double-ratchet-transport) | Device rollback or cache loss may temporarily reopen replay windows.
| Deanonymization | High | Medium | Sealed-sender envelopes, handshake padding. [Sealed-sender envelope](./wire-spec.md#sealed-sender-envelope-v1) [M1 HandshakeInit](./wire-spec.md#m1-handshakeinit) | Global traffic correlation and long-term timing analysis remain possible.
| Traffic analysis | Medium | High | Cover padding buckets, deterministic nonce structure, constant AAD. [M1 HandshakeInit](./wire-spec.md#m1-handshakeinit) [Double Ratchet transport](./wire-spec.md#double-ratchet-transport) [Deterministic nonce derivation](./wire-spec.md#deterministic-nonce-derivation) | Size/timing buckets leak coarse patterns and volume information.
| Denial of service | Medium | Medium | Retry-cookie puzzles, early transcript validation, Double Ratchet bounds. [Retry cookie format](./wire-spec.md#retry-cookie-binary-format) [Handshake overview](./wire-spec.md#handshake-overview) [Double Ratchet transport](./wire-spec.md#double-ratchet-transport) | Large botnets can still saturate bandwidth; puzzles burden resource-constrained clients.

