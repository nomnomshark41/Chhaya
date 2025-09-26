---
layout: default
title: Home
nav_order: 1
permalink: /
---

# Chhaya

Chhaya is a fully peer-to-peer, serverless secure messaging protocol that keeps
metadata sealed, removes centralized infrastructure, and prioritizes resilient
post-quantum cryptography for every delivery path.

## Why Chhaya?

- **End-to-end security:** AES-256-GCM, ML-KEM-1024, X25519, Double Ratchet, and
  BLS quorum signatures keep ciphertext verifiable without exposing metadata.
- **Purely decentralized:** No central servers or rendezvous services. Peers
  discover one another via libp2p and maintain reachability with QUIC + Noise,
  Autonat, and relay v2 circuits.
- **Cover traffic & privacy:** Configurable padding and sealed-sender envelopes
  ensure indistinguishability between real and decoy traffic.

Use the navigation menu to explore how the protocol works, study the threat
model, and read the wire specification.

## Get involved

- Dive into the [source code](https://github.com/openxla/Chhaya).
- Read the [contributing guide](https://github.com/openxla/Chhaya/blob/main/CONTRIBUTING.md) for engineering standards.
- Join discussions, propose improvements, and help harden the protocol.
