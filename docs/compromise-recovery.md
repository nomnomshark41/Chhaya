---
layout: default
title: Compromise Containment & Recovery
parent: Documentation
nav_order: 3
permalink: /docs/compromise-recovery/
---

# Compromise Containment & Recovery

This document specifies how Chhaya's protocol design responds when an endpoint is compromised. The controls described here bound
attacker impact, accelerate detection, and enable clean recovery without relying on any centralized service. They are layered on
 top of the hybrid handshake, Double Ratchet transport, and quorum-backed verifiable key directory (VKD) that already protect
non-compromised devices.

## A. Threat Boundary

We defend at the protocol level against an adversary that gains complete, persistent control of a single device, including all of
its long-term keys, UI access, and ability to issue messages. We explicitly assume the attacker cannot break the underlying
cryptography, compromise the owner's other devices, or coerce the global VKD quorum. Recovery also presumes the owner eventually
regains out-of-band control (e.g., through another trusted device or social recovery quorum) to initiate revocation and rekeying.

The protocol aims to: (1) strictly limit how long a compromised device can impersonate the owner, (2) confine the blast radius to
the affected device, (3) enable fast detection signals, and (4) deliver deterministic recovery steps that honest owners can
execute from uncompromised devices.

## B. Protocol Primitives

The following primitives must be implemented in priority order. Together they provide layered resilience to compromise.

### Per-Device Short-Lived Keys & VKD Device Registry

* **Offline identity master key.** Each account is anchored by an offline master key kept off the device (e.g., hardware token or
  paper seed). The master signs device certificates and authorizes sensitive VKD updates.
* **Per-device PQ-capable certificates.** Every device derives its own ML-KEM-capable device keypair plus an X25519 fallback and
  requests a certificate signed by the master. The certificate carries unique device metadata (`device_id`, attestation blobs,
  and public keys).
* **Short-lived validity windows.** Certificates embed `issued_at` and `expires_at` timestamps with lifetimes measured in hours or
  days. Devices must renew proactively via the master; stale certificates are rejected once their VKD epoch proves expiry.
* **VKD publication.** Certificates are published in VKD leaves so peers can verify proofs (`verify_vkd_proof`) before trusting a
  device. Absence of a live certificate is treated as a hard failure when establishing sessions.

### Fast Automated Device Revocation via VKD Epochs

* **Revocation entries.** VKD epochs support append-only revocation leaves signed by the master key (or recovery quorum). Each
  entry lists the `device_id`s invalidated at the epoch and includes a monotonic counter to prevent replay.
* **Peer enforcement.** Session establishment requires validating VKD proofs of both certificates and the latest revocation set.
  When a revocation leaf names a device, honest peers immediately refuse new sessions and tear down existing transports with that
  device.
* **Automation hooks.** Compromised devices can be revoked rapidly by submitting a signed request through any uncompromised
  device; once the VKD quorum publishes the epoch, the network-wide state converges without central servers.

### Aggressive Ephemeral Prekeys & One-Time KEM Use

* **Limited prekey queues.** Devices publish small batches (e.g., 48) of asynchronous prekeys in the VKD. Each prekey is marked
  for single use and includes an expiry timestamp.
* **One-time consumption.** Initiators must fetch a fresh prekey proof, perform a single ML-KEM encapsulation, and then mark the
  prekey as consumed. Replays or double-use attempts are rejected by peers and pruned from queues.
* **Automatic replenishment.** Devices monitor inventory and replenish prekeys before depletion. Expired prekeys are ignored,
  ensuring stale compromised material cannot bootstrap new sessions.

### Periodic Forced Hybrid KEM Rekey

* **Session lifetime rules.** Protocol state tracks both message counters and wall-clock duration for each Double Ratchet session.
  After `X` messages or `T` minutes (operator configurable), peers must perform a fresh hybrid handshake (ML-KEM + X25519) to
  derive a new root key and mixing secret.
* **State mixing.** Rekeyed transcripts mix the newly derived secret with the current ratchet root using HKDF, providing
  post-compromise security even if an attacker briefly held the symmetric state.
* **Liveness enforcement.** Sessions that fail to renegotiate within the window enter a tombstoned state (see below), forcing new
  handshakes before additional ciphertext is accepted.

### Authenticated Key-Rotation Announcements via VKD

* **Canonical announcements.** Device add/remove operations and master-key rotations are finalized only when included in a signed
  VKD epoch. Peers reject unsigned or out-of-band announcements.
* **Epoch binding.** Each operation records the epoch number, previous epoch hash, and operator signature so that receivers can
  verify inclusion/consistency proofs before updating local trust state.
* **Replay resistance.** Monotonic epoch numbers and append-only proofs prevent attackers from replaying older rotations to roll
  back honest peers.

### Device Presence & Attestation Tokens (Opt-In)

* **Optional attestation.** Device certificates may embed attestation tokens (TPM, Android SafetyNet, iOS DeviceCheck). Peers
  treat these as soft signals, improving trust when available without blocking privacy-preserving or custom hardware clients.
* **Freshness checks.** Attestation tokens carry their own expirations and are reissued alongside certificate renewals, ensuring
  stale attestations cannot masquerade as live devices.

### Proactive Leakage Containment via Ratchet Tombstones

* **Tombstone state.** Sessions maintain a bounded cache of skipped message keys. When the bound is exceeded—or when forced rekey
  fails—peers emit a tombstone marker and invalidate unused keys.
* **Replay prevention.** Tombstoned sessions reject ciphertext derived from old ratchet states, cutting off attackers who attempt
  to replay captured packets after losing live control.
* **Recovery path.** Once tombstoned, peers require a new VKD-validated handshake before exchanging further traffic, guaranteeing
  clean resynchronization.

### Key-Compromise Detection Signals

* **Reachability pings.** Devices periodically exchange signed nonces over established sessions. Missing or invalid responses mark
  the peer as suspicious, triggering user-facing alerts and encouraging revocation checks.
* **Behavioral heuristics.** Deviations such as unexpected certificate rotation requests or failure to replenish prekeys raise
  warnings logged at `warn!` level for operator review.
* **Probabilistic detection.** These signals are advisory rather than authoritative; they complement VKD revocation by shortening
  detection time.

### Social / Threshold Recovery via VKD-Encrypted Shares

* **Secret sharing.** The offline master seed can be split with Shamir Secret Sharing (or threshold public-key encryption) into
  shares assigned to trusted contacts.
* **VKD publication.** Each share is encrypted to the contact's public key and stored as a blob in the VKD. Retrieval proofs allow
  the owner to confirm integrity before requesting shares out-of-band.
* **Recovery workflow.** After compromise, the owner contacts the required quorum, decrypts shares, reconstructs the master, and
  performs a certified device reset without central coordination.

### Explicit Audit Proofs for Critical Operations

* **Audit payload.** Every critical VKD update (device issuance, revocation, master rotation) contains the epoch number, previous
  epoch hash, operator signature (master or threshold), and optionally a VRF output for unlinkability.
* **Peer validation.** Recipients verify inclusion and consistency proofs before honoring the change, guaranteeing global
  agreement on directory state.
* **Forensic trail.** Audit fields provide tamper-evident logs that owners and peers can replay to investigate compromises and
  verify recovery steps.

By enforcing these primitives, Chhaya constrains attacker dwell time, narrows blast radius, and offers deterministic paths for
honest users to detect, contain, and recover from endpoint compromise without sacrificing decentralization.
