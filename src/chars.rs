//! Characters used in PKCE code verifiers.
//!
//! As per the [standard](https://datatracker.ietf.org/doc/html/rfc7636#section-4.1), code verifiers
//! consist of alphanumeric characters and the following special characters: `-`, `.`, `_`, and `~`.
//!
//! The full character set is `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~`.
//!
//! This module provides the [`CHARS`] constant, which contains the aforementioned characters, and
//! the [`check`] function, which can be used to validate code verifiers (except for their length).

use miette::Diagnostic;
use thiserror::Error;

macro_rules! upper_letters {
    () => {
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    };
}

macro_rules! lower_letters {
    () => {
        "abcdefghijklmnopqrstuvwxyz"
    };
}

macro_rules! letters {
    () => {
        concat!(upper_letters!(), lower_letters!())
    };
}

macro_rules! digits {
    () => {
        "0123456789"
    };
}

macro_rules! special {
    () => {
        "-._~"
    };
}

macro_rules! special_pattern {
    () => {
        '-' | '.' | '_' | '~'
    };
}

macro_rules! chars {
    () => {
        concat!(letters!(), digits!(), special!())
    };
}

/// The characters used in PKCE code verifiers.
pub const CHARS: &str = chars!();

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
/// use pkce_std::chars::{CHARS, is_valid};
///
/// assert!(CHARS.chars().all(is_valid));
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
    use super::{is_valid, CHARS};

    #[test]
    fn range() {
        for character in char::MIN..=char::MAX {
            assert_eq!(CHARS.contains(character), is_valid(character));
        }
    }
}
