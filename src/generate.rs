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
    chars::CHARS,
    length::{Bytes, Length},
};

/// Generates `length` random bytes.
pub fn bytes(length: Bytes) -> Vec<u8> {
    let mut rng = thread_rng();

    let mut data = vec![0; length.get()];

    rng.fill_bytes(&mut data);

    data
}

/// Generates random strings of `length` characters from the [`CHARS`] set.
pub fn string(length: Length) -> String {
    let chars: Vec<_> = CHARS.chars().collect();

    let distribution = Uniform::new(0, chars.len());

    thread_rng()
        .sample_iter(&distribution)
        .take(length.get())
        .map(|index| chars[index])
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::{chars::check, length::Length};

    use super::string;

    #[test]
    fn string_passes() {
        check(string(Length::default())).unwrap()
    }
}
