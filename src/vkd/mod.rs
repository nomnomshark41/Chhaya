// This file is part of Chhaya and is licensed under the GNU Affero General Public License v3.0 or later.
// See the LICENSE file in the project root for license details.

/// Disk-backed verification queue for VKD proofs.
pub mod cache;
/// Client-side validation utilities for VKD signed tree heads.
pub mod client;
/// Gossip message verification for VKD signed tree heads.
pub mod gossip;
/// Trusted configuration loading and key management for VKD verification.
pub mod trust;

/// Re-export common client-side VKD validation helpers.
pub use client::{verify_concordance, Concordance, ConcordanceError, MultiLogPolicy, SthBundle};
/// Re-export gossip verification helpers for consumers.
pub use gossip::{verify_sth_announcement, SthAnnouncement, SthValidationError};
/// Re-export VKD trust anchor loading helpers.
pub use trust::{SignedVkdConfig, VkdConfig, VkdConfigError, VkdTrustAnchors};
