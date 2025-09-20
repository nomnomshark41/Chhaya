# How It Works

Chhaya is a fully peer-to-peer secure messaging protocol that avoids all centralized infrastructure. Peers form ad-hoc mesh overlays and coordinate cryptographic directory data without any trusted services.

## Directory Publication and Retrieval

* **Verifiable Key Directory (VKD):** Directory states are represented as append-only VKD epochs. Directory producers publish signed epochs to IPFS, embedding CONIKS-style audit proofs so that receivers can locally verify `verify_vkd_proof` before accepting updates.
* **System Tree Heads (STHs):** The latest VKD summaries (STHs) are announced over libp2p gossipsub. Each announcement is simultaneously pinned to IPNS, giving peers a stable pointer to the freshest epoch hash even when they were offline.
* **Untrusted Transport:** IPFS/IPNS merely move bytes. Every fetched epoch is validated for inclusion, consistency, VRF, log signatures, and quorum witness thresholds prior to acceptance. Invalid proofs are rejected and logged at warn-level without panicking.

## Peer Discovery and Messaging

* **Kademlia DHT:** Nodes advertise their multiaddrs via libp2p Kademlia. Bootstrap happens through previously exchanged peer records or opportunistic LAN discovery (mDNS) when available; there is no central rendezvous service.
* **Relay and NAT Traversal:** Autonat and relay v2 circuits maintain reachability for peers behind NATs while keeping the overlay decentralized. All messaging runs over QUIC+Noise transport with sealed-sender envelopes and deterministic HKDF-n12 nonces.
* **Cover Traffic:** Gossip topics blend directory chatter, cover messages, and application payloads so that metadata remains opaque on the wire.
* **Gossipsub Peer Scoring:** The gossip mesh targets eight neighbours (`mesh_n = 8`, `mesh_n_low = 6`, `mesh_n_high = 12`, `mesh_outbound_min = 3`) and enforces libp2p peer scoring. Behaviour penalties decay over 90s with weight `-20`, invalid payloads incur a `-100` hit, slow delivery adds `-1` penalties, and IP colocation above three peers is penalized with weight `-15`. Thresholds are `gossip ≥ -10`, `publish ≥ -20`, and a graylist at `-40`; peers that fall below graylist are dropped from provider dials and ignored when returning rendezvous results.

## Threat Model Notes

* **Adversarial Directories:** Because directory transport is untrusted, malicious IPFS content cannot corrupt state without passing VKD verification. Witness thresholds and BLS quorum co-signatures prevent single-party equivocation.
* **Network-Level Attackers:** Noise handshakes, Double Ratchet sessions, and sealed-sender envelopes ensure confidentiality and forward secrecy even on hostile networks. QUIC with retry is resistant to amplification and spoofing.
* **Sybil and Eclipse Resistance:** DHT peer scoring, gossip mesh trimming, and quorum attestation mitigate Sybil and eclipse attempts. Honest peers can always rejoin via independent DHT walks and IPNS lookups.
* **Failure Handling:** Verification failures, malformed packets, or unexpected inputs surface as typed errors rather than panics, keeping nodes robust under attack.

