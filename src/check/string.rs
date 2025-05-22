//! Checking PKCE code verifier strings.

use const_macros::{const_map_err, const_try};

#[cfg(feature = "diagnostics")]
use miette::Diagnostic;

use thiserror::Error;

use crate::check::{ascii, bytes};

/// Represents sources of errors that can occur when checking strings.
#[derive(Debug, Error)]
#[error("invalid string encountered")]
#[cfg_attr(feature = "diagnostics", derive(Diagnostic))]
pub enum Error {
    /// Non-ASCII string encountered.
    #[cfg_attr(
        feature = "diagnostics",
        diagnostic(
            code(pkce_std::check::string::ascii),
            help("ensure the string is ASCII")
        )
    )]
    Ascii(#[from] ascii::Error),
    /// Invalid byte encountered.
    #[cfg_attr(
        feature = "diagnostics",
        diagnostic(code(pkce_std::check::string::byte), help("ensure the byte is valid"))
    )]
    Bytes(#[from] bytes::Error),
}

/// Recursively checks that the given string contains valid characters only.
///
/// One may need to increase the recursion limit manually to use this `const` function.
///
/// This is done via applying the `recursion_limit` attribute to the crate:
///
/// ```
/// #![recursion_limit = "256"]
/// ```
///
/// # Errors
///
/// Returns [`enum@Error`] on non-ASCII or otherwise invalid strings.
pub const fn const_check_str(string: &str) -> Result<(), Error> {
    pub const fn check_bytes(bytes: &[u8]) -> Result<(), bytes::Error> {
        match *bytes {
            [] => Ok(()),
            [byte, ref rest @ ..] => {
                const_try!(bytes::check(byte));

                check_bytes(rest)
            }
        }
    }

    const_try!(const_map_err!(ascii::check_str(string) => Error::Ascii));

    const_map_err!(check_bytes(string.as_bytes()) => Error::Bytes)
}

/// Iterarively checks that the given string contains valid characters only.
///
/// # Errors
///
/// Returns [`enum@Error`] on non-ASCII or otherwise invalid codes.
pub fn check_str(string: &str) -> Result<(), Error> {
    fn check_bytes(bytes: &[u8]) -> Result<(), bytes::Error> {
        bytes.iter().copied().try_for_each(bytes::check)
    }

    ascii::check(string)?;

    check_bytes(string.as_bytes())?;

    Ok(())
}

/// Similar to [`check_str`], except it is generic over [`AsRef<str>`].
///
/// # Errors
///
/// Any [`enum@Error`] in [`check_str`] is propagated.
pub fn check<S: AsRef<str>>(string: S) -> Result<(), Error> {
    check_str(string.as_ref())
}
