//! PKCE code verifier lengths.
//!
//! As per the [standard](https://datatracker.ietf.org/doc/html/rfc7636#section-4.1), the length
//! of the code verifier must be at least `43` and at most `128`.
//!
//! The core idea is that `43` and `128` correspond to Base64-encoded lengths of `32` and `96` bytes
//! respectively (padding is not used).
//!
//! Therefore this module provides two types: [`Bytes`], which represents the number of bytes before
//! encoding and effectively creating the code verifier, and [`Length`], which represents the actual
//! length of the code verifier.
//!
//! [`Length`] can be created from [`Bytes`], but not vice versa. Both types internally store
//! [`usize`] values, which are guaranteed to be in the valid range:
//!
//! | `TYPE`     | `MIN` | `DEFAULT` | `MAX` |
//! |------------|-------|-----------|-------|
//! | [`Bytes`]  | `32`  | `64`      | `96`  |
//! | [`Length`] | `43`  | `86`      | `128` |
//!
//! Each [`Length`] value above is computed from the corresponding [`Bytes`] value constantly
//! using the [`encoding::length`] function.
//!
//! ```
//! use pkce_std::length::{Bytes, Length};
//!
//! let bytes = Bytes::new(64).unwrap();
//!
//! let length: Length = bytes.into();
//!
//! assert_eq!(length.get(), 86);
//! ```

use std::{fmt, num::ParseIntError, str::FromStr};

use miette::Diagnostic;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use thiserror::Error;

use crate::{encoding, int};

/// The minimum bytes length.
pub const MIN_BYTES: usize = 32;

/// The default bytes length.
pub const DEFAULT_BYTES: usize = 64;

/// The maximum bytes length.
pub const MAX_BYTES: usize = 96;

/// The minimum length.
pub const MIN: usize = encoding::length(MIN_BYTES);

/// The default length.
pub const DEFAULT: usize = encoding::length(DEFAULT_BYTES);

/// The maximum length.
pub const MAX: usize = encoding::length(MAX_BYTES);

/// Represents errors that can occur when constructing [`Bytes`] values.
///
/// This error is returned when the given value is less than [`MIN_BYTES`]
/// or greater than [`MAX_BYTES`].
#[derive(Debug, Error, Diagnostic)]
#[error("expected bytes length in `[{MIN_BYTES}, {MAX_BYTES}]` range, got `{value}`")]
#[diagnostic(
    code(pkce_std::length::bytes),
    help("make sure the bytes length is at least `{MIN_BYTES}` and at most `{MAX_BYTES}`")
)]
pub struct BytesError {
    /// The invalid value.
    pub value: usize,
}

impl BytesError {
    /// Constructs [`Self`].
    pub const fn new(value: usize) -> Self {
        Self { value }
    }
}

/// Represents sources of errors that can occur when parsing [`Bytes`] values.
#[derive(Debug, Error, Diagnostic)]
#[error(transparent)]
#[diagnostic(transparent)]
pub enum ParseBytesErrorSource {
    /// Invalid bytes value.
    Bytes(#[from] BytesError),
    /// Integer parse error.
    Int(#[from] int::ParseError),
}

/// Represents errors that can occur when parsing [`Bytes`] values.
///
/// There are two possible sources of this error:
///
/// - The [`string`] could not be parsed into an integer.
/// - The parsed integer value is not valid in [`Bytes`].
///
/// [`string`]: Self::string
#[derive(Debug, Error, Diagnostic)]
#[error("failed to parse `{string}` to bytes length")]
#[diagnostic(
    code(pkce_std::length::bytes::parse),
    help("see the report for more information")
)]
pub struct ParseBytesError {
    /// The source of this error.
    #[source]
    #[diagnostic_source]
    pub source: ParseBytesErrorSource,
    /// The string that could not be parsed.
    pub string: String,
}

impl ParseBytesError {
    /// Constructs [`Self`].
    pub fn new(source: ParseBytesErrorSource, string: String) -> Self {
        Self { source, string }
    }

    /// Constructs [`Self`] from [`BytesError`].
    pub fn bytes(error: BytesError, string: String) -> Self {
        Self::new(error.into(), string)
    }

    /// Constructs [`Self`] from [`int::ParseError`].
    pub fn int(error: int::ParseError, string: String) -> Self {
        Self::new(error.into(), string)
    }

    /// Constructs [`int::ParseError`] from [`ParseIntError`] and constructs [`Self`] from it.
    pub fn new_int(error: ParseIntError, string: String) -> Self {
        Self::int(error.into(), string)
    }
}

/// Represents errors that can occur when constructing [`Length`] values.
///
/// This error is returned when the given value is less than [`MIN`] or greater than [`MAX`].
#[derive(Debug, Error, Diagnostic)]
#[error("expected length in `[{MIN}, {MAX}]` range, got `{value}`")]
#[diagnostic(
    code(pkce_std::length),
    help("make sure the length is at least `{MIN}` and at most `{MAX}`")
)]
pub struct Error {
    /// The invalid value.
    pub value: usize,
}

impl Error {
    /// Constructs [`Self`].
    pub const fn new(value: usize) -> Self {
        Self { value }
    }
}

/// Represents sources of errors that can occur when parsing [`Length`] values.
#[derive(Debug, Error, Diagnostic)]
#[error(transparent)]
#[diagnostic(transparent)]
pub enum ParseErrorSource {
    /// Invalid length error.
    Length(#[from] Error),
    /// Integer parse error.
    Int(#[from] int::ParseError),
}

/// Represents errors that can occur when parsing [`Length`] values.
///
/// There are two possible sources of this error:
///
/// - The [`string`] could not be parsed into an integer.
/// - The parsed integer value is not valid in [`Length`].
///
/// [`string`]: Self::string
#[derive(Debug, Error, Diagnostic)]
#[error("failed to parse `{string}` to length")]
#[diagnostic(
    code(pkce_std::length::parse),
    help("see the report for more information")
)]
pub struct ParseError {
    /// The source of this error.
    #[source]
    #[diagnostic_source]
    pub source: ParseErrorSource,
    /// The string that could not be parsed.
    pub string: String,
}

impl ParseError {
    /// Constructs [`Self`].
    pub fn new(source: ParseErrorSource, string: String) -> Self {
        Self { source, string }
    }

    /// Constructs [`Self`] from [`struct@Error`].
    pub fn length(error: Error, string: String) -> Self {
        Self::new(error.into(), string)
    }

    /// Constructs [`Self`] from [`int::ParseError`].
    pub fn int(error: int::ParseError, string: String) -> Self {
        Self::new(error.into(), string)
    }

    /// Constructs [`int::ParseError`] from [`ParseIntError`] and constructs [`Self`] from it.
    pub fn new_int(error: ParseIntError, string: String) -> Self {
        Self::int(error.into(), string)
    }
}

/// Represents bytes lengths.
///
/// Refer to the [module] documentation for more information.
///
/// # Examples
///
/// ```
/// use pkce_std::length::Bytes;
///
/// let bytes = Bytes::new(96).unwrap();
///
/// assert_eq!(bytes.get(), 96);
/// assert_eq!(bytes.encoded(), 128);
/// ```
///
/// [module]: self
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "usize", into = "usize"))]
pub struct Bytes {
    value: usize,
}

/// Represents lengths.
///
/// Refer to the [module] documentation for more information.
///
/// # Examples
///
/// ```
/// use pkce_std::length::Length;
///
/// let length = Length::new(69).unwrap();
///
/// assert_eq!(length.get(), 69);
/// ```
///
/// [module]: self
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "usize", into = "usize"))]
pub struct Length {
    value: usize,
}

impl TryFrom<usize> for Bytes {
    type Error = BytesError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Bytes> for usize {
    fn from(bytes: Bytes) -> Self {
        bytes.value
    }
}

impl TryFrom<usize> for Length {
    type Error = Error;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Length> for usize {
    fn from(length: Length) -> Self {
        length.value
    }
}

impl fmt::Display for Bytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(formatter)
    }
}

impl fmt::Display for Length {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(formatter)
    }
}

impl Default for Bytes {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl Default for Length {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl FromStr for Bytes {
    type Err = ParseBytesError;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let value = string
            .parse()
            .map_err(|error| Self::Err::new_int(error, string.to_owned()))?;

        Self::new(value).map_err(|error| Self::Err::bytes(error, string.to_owned()))
    }
}

impl FromStr for Length {
    type Err = ParseError;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let value = string
            .parse()
            .map_err(|error| Self::Err::new_int(error, string.to_owned()))?;

        Self::new(value).map_err(|error| Self::Err::length(error, string.to_owned()))
    }
}

impl Bytes {
    /// Constructs [`Self`] if the provided value is in the valid range.
    ///
    /// # Errors
    ///
    /// [`BytesError`] is returned if the value is less than [`MIN_BYTES`]
    /// or greater than [`MAX_BYTES`].
    pub const fn new(value: usize) -> Result<Self, BytesError> {
        if value < MIN_BYTES || value > MAX_BYTES {
            Err(BytesError::new(value))
        } else {
            // SAFETY: `value` is in the valid range for `Self`
            Ok(unsafe { Self::new_unchecked(value) })
        }
    }

    /// Constructs [`Self`] without checking the value.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the value is in the valid range for [`Self`].
    pub const unsafe fn new_unchecked(value: usize) -> Self {
        Self { value }
    }

    /// Checks whether the given value is in the valid range for [`Self`].
    ///
    /// This function simply calls [`Self::new`], propagating errors and discarding the result.
    ///
    /// # Errors
    ///
    /// See [`Self::new`] for more information.
    pub fn check(value: usize) -> Result<(), BytesError> {
        let _ = Self::new(value)?;

        Ok(())
    }

    /// Consumes [`Self`] and returns the contained value.
    pub const fn get(self) -> usize {
        self.value
    }

    /// Consumes [`Self`], computing the [`Length`] value corresponding to the contained one.
    pub const fn encoded(self) -> usize {
        encoding::length(self.get())
    }

    /// The minimum value of [`Self`].
    // SAFETY: `MIN_BYTES` is the smallest valid value for `Self`
    pub const MIN: Self = unsafe { Self::new_unchecked(MIN_BYTES) };

    /// The default value of [`Self`].
    // SAFETY: `DEFAULT_BYTES` is in the `[MIN_BYTES, MAX_BYTES]` range, therefore it is valid
    pub const DEFAULT: Self = unsafe { Self::new_unchecked(DEFAULT_BYTES) };

    /// The maximum value of [`Self`].
    // SAFETY: `MAX_BYTES` is the largest valid value for `Self`
    pub const MAX: Self = unsafe { Self::new_unchecked(MAX_BYTES) };
}

impl From<Bytes> for Length {
    fn from(bytes: Bytes) -> Self {
        // SAFETY: `bytes.encoded()` is in the valid range for `Self`
        unsafe { Self::new_unchecked(bytes.encoded()) }
    }
}

impl Length {
    /// Constructs [`Self`] if the provided value is in the valid range.
    ///
    /// # Errors
    ///
    /// [`struct@Error`] is returned if the value is less than [`MIN`] or greater than [`MAX`].
    pub const fn new(value: usize) -> Result<Self, Error> {
        if value < MIN || value > MAX {
            Err(Error::new(value))
        } else {
            // SAFETY: `value` is in the valid range for `Self`
            Ok(unsafe { Self::new_unchecked(value) })
        }
    }

    /// Constructs [`Self`] without checking the value.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the value is in the valid range for [`Self`].
    pub const unsafe fn new_unchecked(value: usize) -> Self {
        Self { value }
    }

    /// Checks whether the given value is in the valid range for [`Self`].
    ///
    /// This function simply calls [`Self::new`], propagating errors and discarding the result.
    ///
    /// # Errors
    ///
    /// See [`Self::new`] for more information.
    pub fn check(value: usize) -> Result<(), Error> {
        let _ = Self::new(value)?;

        Ok(())
    }

    /// Consumes [`Self`] and returns the contained value.
    pub const fn get(self) -> usize {
        self.value
    }

    /// The minimum value of [`Self`].
    // SAFETY: `MIN` is the smallest valid value for `Self`
    pub const MIN: Self = unsafe { Self::new_unchecked(MIN) };

    /// The default value of [`Self`].
    // SAFETY: `DEFAULT` is in between `MIN` and `MAX`, therefore it is valid
    pub const DEFAULT: Self = unsafe { Self::new_unchecked(DEFAULT) };

    /// The maximum value of [`Self`].
    // SAFETY: `MAX` is the largest valid value for `Self`
    pub const MAX: Self = unsafe { Self::new_unchecked(MAX) };
}
