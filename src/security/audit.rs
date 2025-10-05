// This file is part of Chhaya and is licensed under the GNU Affero General Public License v3.0 or later.
// See the LICENSE file in the project root for license details.

use zeroize::Zeroizing;

#[cfg(test)]
use zeroize::Zeroize;

/// Memory-protected shared secret derived from the ML-KEM handshake.
pub type SharedSecret = Zeroizing<Vec<u8>>;

/// Shamir share of the retry-cookie MAC key stored with zeroization semantics.
pub type ServerSecretShare = Zeroizing<Vec<u8>>;

/// Human-readable labels used when auditing secret containers.
pub const SECRET_TYPE_NAMES: &[&str] = &[
    "SharedSecret (ML-KEM derived shared secret bytes)",
    "ServerSecretShare (Shamir share of retry-cookie MAC key)",
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct SpyBuffer {
        bytes: Vec<u8>,
        log: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl Zeroize for SpyBuffer {
        fn zeroize(&mut self) {
            self.bytes.zeroize();
            self.log.lock().unwrap().push(self.bytes.clone());
        }
    }

    #[test]
    fn secret_containers_zeroize_between_allocations() {
        let log = Arc::new(Mutex::new(Vec::new()));

        {
            let first = SpyBuffer {
                bytes: vec![0xAA; 64],
                log: Arc::clone(&log),
            };
            drop(Zeroizing::new(first));
        }

        {
            let second = SpyBuffer {
                bytes: vec![0x55; 64],
                log: Arc::clone(&log),
            };
            drop(Zeroizing::new(second));
        }

        let records = log.lock().unwrap();
        assert_eq!(records.len(), 2);
        for record in records.iter() {
            assert!(record.iter().all(|&byte| byte == 0));
        }
        drop(records);

        let mut secrets = Vec::new();
        for pattern in [0x11u8, 0x22u8] {
            let secret: SharedSecret = Zeroizing::new(vec![pattern; 32]);
            secrets.push(secret);
        }
        drop(secrets);

        let mut shares = Vec::new();
        for pattern in [0x33u8, 0x44u8, 0x55u8] {
            let share: ServerSecretShare = Zeroizing::new(vec![pattern; 32]);
            shares.push(share);
        }
        drop(shares);
    }
}
