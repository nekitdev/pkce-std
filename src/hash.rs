//! Hashing functionality.

use sha2::{Digest, Sha256};

/// The number of bits in one byte.
pub const BYTE_BITS: usize = 8;

/// The number of bits in the hash.
pub const BITS: usize = 256;

/// The length of the hash in bytes.
pub const LENGTH: usize = BITS / BYTE_BITS;

/// The output type of the [`hash`] function.
pub type Output = [u8; LENGTH];

/// Hashes the given data using SHA-256.
pub fn hash<D: AsRef<[u8]>>(data: D) -> Output {
    Sha256::digest(data).into()
}
