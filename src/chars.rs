//! Characters used in PKCE code verifiers.
//!
//! As per the [standard](https://datatracker.ietf.org/doc/html/rfc7636#section-4.1), code verifiers
//! consist of alphanumeric characters and the following special characters: `-`, `.`, `_`, and `~`.
//!
//! The full character set is `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~`.
//!
//! This module provides the [`CHARS`] constant (along with the [`STRING`] constant), which contain
//! the aforementioned characters, and the [`check`] function, which can be used to check
//! code verifiers for validity (except for their length).

use miette::Diagnostic;
use thiserror::Error;

use crate::macros::const_assert;

macro_rules! special_pattern {
    () => {
        '-' | '.' | '_' | '~'
    };
}

/// The amount of valid characters in PKCE code verifiers.
pub const LENGTH: usize = 66;

// constantly assert that the length is non-zero (required for `generate::string` to be safe)
const_assert!(LENGTH > 0);

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

/// Represents errors that can occur when invalid characters are encountered.
#[derive(Debug, Error, Diagnostic)]
#[error("invalid character `{character}`")]
#[diagnostic(code(pkce_std::chars), help("ensure the string is valid"))]
pub struct Error {
    /// The first invalid character encountered.
    pub character: char,
}

impl Error {
    /// Consturcts [`Self`].
    pub const fn new(character: char) -> Self {
        Self { character }
    }
}

/// Checks if the given character is special, i.e. one of `-`, `.`, `_`, or `~`.
pub const fn is_special(character: char) -> bool {
    matches!(character, special_pattern!())
}

/// Checks if the given character is valid, i.e. either alphanumeric or special.
///
/// # Examples
///
/// ```
/// use pkce_std::chars::{is_valid, STRING};
///
/// assert!(STRING.chars().all(is_valid));
/// ```
pub const fn is_valid(character: char) -> bool {
    character.is_ascii_alphanumeric() || is_special(character)
}

/// Checks that the given string contains only characters specified in [`CHARS`].
///
/// # Errors
///
/// Returns [`struct@Error`] if any invalid character is encountered.
///
/// # Examples
///
/// ```
/// use pkce_std::chars::check;
///
/// let verifier = "SSBsb3ZlIHdyaXRpbmcgb3BlbiBzb3VyY2Ugc29mdHdhcmUhIF4uXiB-IG5la2l0";
///
/// check(verifier).unwrap();
///
/// let invalid = "nekitdev/pkce-std";
/// let unexpected = '/';
///
/// let error = check(invalid).unwrap_err();
///
/// assert_eq!(error.character, unexpected);
/// ```
pub fn check<S: AsRef<str>>(string: S) -> Result<(), Error> {
    string.as_ref().chars().try_for_each(|character| {
        is_valid(character)
            .then_some(())
            .ok_or_else(|| Error::new(character))
    })
}

#[cfg(test)]
mod tests {
    use super::{is_valid, CHARS, STRING};

    fn is_valid_chars(character: char) -> bool {
        CHARS.contains(&character)
    }

    fn is_valid_string(character: char) -> bool {
        STRING.contains(character)
    }

    #[test]
    fn consistency() {
        for character in char::MIN..=char::MAX {
            assert_eq!(is_valid_chars(character), is_valid(character));
            assert_eq!(is_valid_string(character), is_valid(character));
        }
    }
}
