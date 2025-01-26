//! Generating random bytes and strings.
//!
//! This module provides two functions for generating random bytes and strings:
//! [`bytes`] and [`string`] accepting the desired length as [`Bytes`] and [`Length`] respectively.
//!
//! Because of the imposed length restrictions, the functions are safe to use
//! in the context of this crate. See [`length`] for more information.
//!
//! [`length`]: crate::length

use rand::{distributions::Uniform, thread_rng, Rng, RngCore};

use crate::{
    chars::{CHARS, LENGTH},
    length::{Bytes, Length},
};

/// Generates `count` random bytes.
pub fn bytes(count: Bytes) -> Vec<u8> {
    let mut rng = thread_rng();

    let mut data = vec![0; count.get()];

    rng.fill_bytes(&mut data);

    data
}

/// Generates random strings of `length` characters from the [`CHARS`] set.
pub fn string(length: Length) -> String {
    let distribution = Uniform::new(0, LENGTH);

    thread_rng()
        .sample_iter(&distribution)
        .take(length.get())
        .map(|index| CHARS[index])
        .collect()
}
