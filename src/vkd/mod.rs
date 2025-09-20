/// Disk-backed verification queue for VKD proofs.
pub mod cache;
/// Client-side validation utilities for VKD signed tree heads.
pub mod client;
/// Gossip message verification for VKD signed tree heads.
pub mod gossip;

/// Re-export common client-side VKD validation helpers.
pub use client::{verify_concordance, Concordance, ConcordanceError, MultiLogPolicy, SthBundle};
/// Re-export gossip verification helpers for consumers.
pub use gossip::{
    default_sth_log_id, default_sth_log_public_key, default_sth_witness_public_keys,
    default_sth_witness_threshold, verify_sth_announcement, SthAnnouncement, SthValidationError,
};
