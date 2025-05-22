//! Checking strings to be ASCII.

use const_macros::const_early;

#[cfg(feature = "diagnostics")]
use miette::Diagnostic;

use thiserror::Error;

/// Represents errors that occur when non-ASCII strings are encountered.
#[derive(Debug, Error)]
#[error("non-ascii string encountered")]
#[cfg_attr(
    feature = "diagnostics",
    derive(Diagnostic),
    diagnostic(code(pkce_std::check::ascii), help("ensure the string is ASCII"))
)]
pub struct Error;

/// Checks that the given string is ASCII.
///
/// # Examples
///
/// ```
/// use pkce_std::check::ascii::check_str;
///
/// let string = "<3";
/// let unicode = "❤️";
///
/// assert!(check_str(string).is_ok());
/// assert!(check_str(unicode).is_err());
/// ```
///
/// # Errors
///
/// Returns [`struct@Error`] if the string is non-ASCII.
pub const fn check_str(string: &str) -> Result<(), Error> {
    const_early!(!string.is_ascii() => Error);

    Ok(())
}

/// Similar to [`check_str`], except it is generic over [`AsRef<str>`].
///
/// # Errors
///
/// Any [`struct@Error`] returned from [`check_str`] is propagated.
pub fn check<S: AsRef<str>>(string: S) -> Result<(), Error> {
    check_str(string.as_ref())
}
