//! Checking PKCE code verifiers using bytes instead of characters.

use const_macros::const_early;

#[cfg(feature = "diagnostics")]
use miette::Diagnostic;

use thiserror::Error;

/// Represents errors that occur when invalid bytes are encountered.
#[derive(Debug, Error)]
#[error("invalid byte `{byte}` encountered")]
#[cfg_attr(
    feature = "diagnostics",
    derive(Diagnostic),
    diagnostic(code(pkce_std::check::bytes), help("ensure the byte is valid"))
)]
pub struct Error {
    /// The invalid byte.
    pub byte: u8,
}

impl Error {
    /// Constructs [`Self`].
    pub const fn new(byte: u8) -> Self {
        Self { byte }
    }
}

macro_rules! special_pattern {
    () => {
        b'-' | b'.' | b'_' | b'~'
    };
}

/// Checks if the given byte is special, i.e. one of `-`, `.`, `_`, or `~`.
pub const fn is_special(byte: u8) -> bool {
    matches!(byte, special_pattern!())
}

/// Checks if the given byte is valid, i.e. either alphanumeric or special.
pub const fn is_valid(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || is_special(byte)
}

/// Checks that the given byte is valid.
///
/// # Examples
///
/// ```
/// use pkce_std::check::bytes::check;
///
/// let minus = b'-';
/// let plus = b'+';
///
/// assert!(check(minus).is_ok());
/// assert!(check(plus).is_err());
/// ```
///
/// # Errors
///
/// Returns [`struct@Error`] if the byte is invalid.
pub const fn check(byte: u8) -> Result<(), Error> {
    const_early!(!is_valid(byte) => Error::new(byte));

    Ok(())
}
