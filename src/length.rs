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

use std::{fmt, str::FromStr};

use const_macros::{const_early, const_ok, const_try};
use miette::Diagnostic;

#[cfg(feature = "serde")]
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use thiserror::Error;

use crate::{encoding, int, macros::errors};

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
    pub const fn new(source: ParseBytesErrorSource, string: String) -> Self {
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
    pub const fn new(source: ParseErrorSource, string: String) -> Self {
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
}

/// Represents lengths in bytes.
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
pub struct Length {
    value: usize,
}

#[cfg(feature = "serde")]
impl Serialize for Bytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.get().serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = usize::deserialize(deserializer)?;

        Self::new(value).map_err(de::Error::custom)
    }
}

impl TryFrom<usize> for Bytes {
    type Error = BytesError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Bytes> for usize {
    fn from(bytes: Bytes) -> Self {
        bytes.get()
    }
}

#[cfg(feature = "serde")]
impl Serialize for Length {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.get().serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Length {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = usize::deserialize(deserializer)?;

        Self::new(value).map_err(de::Error::custom)
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
        length.get()
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

errors! {
    Type = ParseBytesError,
    Hack = $,
    parse_bytes_error => bytes(error, string => to_owned),
    parse_bytes_int_error => int(error, string => to_owned),
}

impl FromStr for Bytes {
    type Err = ParseBytesError;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let value = string
            .parse()
            .map_err(|error| parse_bytes_int_error!(int::wrap(error), string))?;

        Self::new(value).map_err(|error| parse_bytes_error!(error, string))
    }
}

errors! {
    Type = ParseError,
    Hack = $,
    parse_error => length(error, string => to_owned),
    parse_int_error => int(error, string => to_owned),
}

impl FromStr for Length {
    type Err = ParseError;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let value = string
            .parse()
            .map_err(|error| parse_int_error!(int::wrap(error), string))?;

        Self::new(value).map_err(|error| parse_error!(error, string))
    }
}

errors! {
    Type = BytesError,
    Hack = $,
    bytes_error => new(value),
}

impl Bytes {
    /// Constructs [`Self`] if the provided value is in the valid range.
    ///
    /// # Errors
    ///
    /// See [`check`] for more information.
    ///
    /// [`check`]: Self::check
    pub const fn new(value: usize) -> Result<Self, BytesError> {
        const_try!(Self::check(value));

        // SAFETY: `value` is in the valid range for `Self`
        Ok(unsafe { Self::new_unchecked(value) })
    }

    /// Similar to [`new`], but the error is discarded.
    ///
    /// [`new`]: Self::new
    pub const fn new_ok(value: usize) -> Option<Self> {
        const_ok!(Self::new(value))
    }

    /// Checks whether the given value is in the valid range for [`Self`].
    ///
    /// # Errors
    ///
    /// [`BytesError`] is returned if the value is less than [`MIN_BYTES`]
    /// or greater than [`MAX_BYTES`].
    pub const fn check(value: usize) -> Result<(), BytesError> {
        const_early!(value < MIN_BYTES || value > MAX_BYTES => bytes_error!(value));

        Ok(())
    }

    /// Constructs [`Self`] without checking the value.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the value is in the valid range for [`Self`].
    pub const unsafe fn new_unchecked(value: usize) -> Self {
        Self { value }
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

errors! {
    Type = Error,
    Hack = $,
    error => new(value),
}

impl Length {
    /// Constructs [`Self`] if the provided value is in the valid range.
    ///
    /// # Errors
    ///
    /// See [`check`] for more information.
    ///
    /// [`check`]: Self::check
    pub const fn new(value: usize) -> Result<Self, Error> {
        const_try!(Self::check(value));

        // SAFETY: `value` is in the valid range for `Self`
        Ok(unsafe { Self::new_unchecked(value) })
    }

    /// Similar to [`new`], but the error is discarded.
    ///
    /// [`new`]: Self::new
    pub const fn new_ok(value: usize) -> Option<Self> {
        const_ok!(Self::new(value))
    }

    /// Checks whether the given value is in the valid range for [`Self`].
    ///
    /// # Errors
    ///
    /// [`struct@Error`] is returned if the value is less than [`MIN`] or greater than [`MAX`].
    pub const fn check(value: usize) -> Result<(), Error> {
        const_early!(value < MIN || value > MAX => error!(value));

        Ok(())
    }

    /// Constructs [`Self`] without checking the value.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the value is in the valid range for [`Self`].
    pub const unsafe fn new_unchecked(value: usize) -> Self {
        Self { value }
    }

    /// Consumes [`Self`] and returns the contained value.
    pub const fn get(self) -> usize {
        self.value
    }

    /// The minimum value of [`Self`].
    pub const MIN: Self = Self::new_ok(MIN).unwrap();

    /// The default value of [`Self`].
    pub const DEFAULT: Self = Self::new_ok(DEFAULT).unwrap();

    /// The maximum value of [`Self`].
    pub const MAX: Self = Self::new_ok(MAX).unwrap();
}
