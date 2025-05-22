//! Hashing functionality.

use sha2::{Digest, Sha256};

/// Hashes the given data using SHA-256.
pub fn sha256<D: AsRef<[u8]>>(data: D) -> impl AsRef<[u8]> {
    Sha256::digest(data)
}
