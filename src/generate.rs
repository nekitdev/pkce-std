//! Generating random bytes and strings.
//!
//! This module provides two functions for generating random bytes and strings:
//! [`bytes`] and [`string`] accepting the desired length as [`Count`] and [`Length`] respectively.
//!
//! Because of the imposed length restrictions, the functions are safe to use
//! in the context of this crate. See [`count`] and [`length`] for more information.
//!
//! [`count`]: crate::count
//! [`length`]: crate::length

#[cfg(feature = "unsafe-assert")]
use std::hint::assert_unchecked;

use rand::{Rng, RngCore, distr::Uniform, rng};

use crate::{
    check::chars::{CHARS, LENGTH},
    count::Count,
    length::Length,
};

/// Generates `count` random bytes.
pub fn bytes(count: Count) -> Vec<u8> {
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
///
/// ## Feature
///
/// Moreover, the `unsafe-assert` feature can be enabled to `assume` the bounds are correct.
pub fn string(length: Length) -> String {
    let distribution = Uniform::new(0, LENGTH).unwrap();

    rng()
        .sample_iter(distribution)
        .take(length.get())
        .map(|index| {
            #[cfg(feature = "unsafe-assert")]
            unsafe {
                assert_unchecked(index < LENGTH);
            }

            CHARS[index]
        })
        .collect()
}
