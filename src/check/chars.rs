//! Characters used in PKCE code verifiers.
//!
//! As per the [standard](https://datatracker.ietf.org/doc/html/rfc7636#section-4.1), code verifiers
//! consist of alphanumeric characters and the following special characters: `-`, `.`, `_`, and `~`.
//!
//! The full character set is `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~`.
//!
//! This module provides the [`CHARS`] constant (along with the [`STRING`] constant), which contain
//! the aforementioned characters.

use const_macros::{const_assert_eq, const_assert_ne};

/// The amount of valid characters in PKCE code verifiers.
pub const LENGTH: usize = 66;

// constantly assert that the length is non-zero (required for `generate::string` to be safe)
const_assert_ne!(LENGTH, 0);

/// The characters used in PKCE code verifiers.
#[rustfmt::skip]
pub const CHARS: [char; LENGTH] = [
    // upper
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
    'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
    'U', 'V', 'W', 'X', 'Y', 'Z',
    // lower
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
    'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
    'u', 'v', 'w', 'x', 'y', 'z',
    // digit
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    // special
    '-', '.', '_', '~',
];

/// The string representation of [`CHARS`].
pub const STRING: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

const_assert_eq!(STRING.len(), LENGTH);

#[cfg(test)]
mod tests {
    use crate::check::{
        bytes::is_valid,
        chars::{CHARS, STRING},
    };

    #[test]
    fn equality() {
        let string: String = CHARS.into_iter().collect();

        assert_eq!(string, STRING);
    }

    #[test]
    fn validity() {
        assert!(STRING.bytes().all(is_valid));
    }
}
