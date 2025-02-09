//! Generating random bytes and strings.
//!
//! This module provides two functions for generating random bytes and strings:
//! [`bytes`] and [`string`] accepting the desired length as [`Bytes`] and [`Length`] respectively.
//!
//! Because of the imposed length restrictions, the functions are safe to use
//! in the context of this crate. See [`length`] for more information.
//!
//! [`length`]: crate::length

use rand::{distr::Uniform, rng, Rng, RngCore};

use crate::{
    chars::{CHARS, LENGTH},
    length::{Bytes, Length},
};

/// Generates `count` random bytes.
pub fn bytes(count: Bytes) -> Vec<u8> {
    let mut data = vec![0; count.get()];

    rng().fill_bytes(&mut data);

    data
}

/// Generates random strings of `length` characters from the [`CHARS`] set.
///
/// # Panics
///
/// This function will not panic, as detailed below.
///
/// ## Distribution
///
/// The uniform distribution is created with constantly checked [`LENGTH`] being non-zero.
///
/// ## Bounds
///
/// [`CHARS`] is the array containing exactly [`LENGTH`] characters. Since the uniform range
/// is exclusive, the sampled index will always be in the bounds of the array.
pub fn string(length: Length) -> String {
    let distribution = Uniform::new(0, LENGTH).unwrap();

    rng()
        .sample_iter(distribution)
        .take(length.get())
        .map(|index| CHARS[index])
        .collect()
}
