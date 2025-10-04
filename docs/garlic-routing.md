---
layout: default
title: Garlic Routing
author: Chhaya Team
parent: Documentation
nav_order: 3
permalink: /docs/garlic-routing/
---

# Garlic Routing

The `routing` crate module encapsulates how Chhaya moves sealed-sender payloads
through the relay mesh without ever disclosing metadata in the clear. The module
introduces a layered garlic design that mirrors Tor-style onion routing while
supporting bulb bundling and circuit-level cover traffic.

## Circuit Lifecycle

1. **Discovery:** The router asks the libp2p Kademlia network for a set of relay
   descriptors. Each descriptor ships with a Verifiable Key Directory (VKD)
   proof bundle that authenticates the advertised public keys, relay features,
   and drop slots.
2. **Verification:** Before a descriptor is admitted, the router invokes
   `VkdDescriptorVerifier::verify_before_accept`, which chains
   `verify_vkd_proof` against the locally pinned trust anchors. Descriptors that
   fail validation never enter the circuit pool.
3. **Assembly:** The router samples `default_hop_count` descriptors and creates a
   `Circuit`. The first hop acts as the entry relay, the last hop either delivers
   directly to the destination or drops bulbs into the rendezvous slots
   advertised in the descriptors.
4. **Teardown:** Circuits expose a `teardown_circuit` helper that cancels the
   Tokio task responsible for emitting cover bulbs. This keeps resource usage in
   check when sessions end or peers rotate paths proactively.

## Garlic Bulbs and Cloves

* **Cloves:** Each message envelope is transported as a clove. Cloves embed the
  Double Ratchet header alongside ciphertext so that the router does not have to
  peek into session metadata.
* **Bulbs:** A bulb bundles one or more cloves and wraps them in per-hop onion
  layers. `BulbBuilder` derives the onion keys using HKDF keyed by the circuit
  identifier, hop position, and a fresh salt, ensuring indistinguishability even
  across cover bulbs.
* **Cover Generation:** `Bulb::cover` creates synthetic cloves filled with random
  data. The cover bulbs share the same layering logic as real traffic, so an
  observer cannot tell them apart on the wire.

## Timing Defences

* **Constant Rate:** Every circuit spawns a Tokio task that sends cover bulbs at
  a deterministic interval (`cover_interval`).
* **Poisson Mixing:** Before each emission the scheduler draws an additional
  delay from an exponential distribution (`poisson_lambda`) so bursts do not line
  up perfectly with user activity. The result is a constant-rate baseline with
  timing noise that frustrates traffic correlation attacks.

## Replay and Abuse Controls

* **Replay Cache:** The router tracks the fingerprints of the most recent bulbs
  for `replay_ttl` seconds. Duplicates are discarded with a typed
  `RoutingError::ReplayDetected`.
* **Stateless Puzzles:** When relays throttle clients, they can issue HKDF-based
  challenges that are verifiable without storing per-peer state.
* **Drop Slots:** Descriptors advertise VRF-derived drop slots so peers can stage
  store-and-forward bulbs without interactive rendezvous, keeping the system
  asynchronous and metadata-free.

Together, these pieces deliver a multi-hop garlic routing core that matches
Chhaya’s zero-trust, metadata-minimising requirements while remaining entirely
serverless.
