//! PKCE code verifier bytes count.
//!
//! As per the [standard](https://datatracker.ietf.org/doc/html/rfc7636#section-4.1), the length
//! of the code verifier must be at least `43` and at most `128`.
//!
//! The core idea is that `43` and `128` correspond to Base64-encoded lengths of `32` and `96` bytes
//! respectively (padding is not used).
//!
//! This module provides the [`Count`] type, which represents the number of bytes before
//! encoding and effectively creating the code verifier.
//!
//! [`Count`] can be converted to [`Length`], but not vice versa.
//!
//! The type internally stores [`usize`] values, which are guaranteed to be in the range
//! from [`MIN`] to [`MAX`] inclusively, defaulting to [`DEFAULT`].
//!
//! # Example
//!
//! Converting from [`Count`] to [`Length`] value:
//!
//! ```
//! use pkce_std::{count::Count, length::Length};
//!
//! let count = Count::default();
//!
//! let length: Length = count.into();
//!
//! assert_eq!(count.encoded(), length.get());
//! ```

use std::{fmt, num::ParseIntError, str::FromStr};

use const_macros::{const_early, const_ok, const_try};

#[cfg(feature = "diagnostics")]
use miette::Diagnostic;

#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use thiserror::Error;

use crate::{encoding, length::Length};

/// The minimum count.
pub const MIN: usize = 32;

/// The default count.
pub const DEFAULT: usize = 64;

/// The maximum count.
pub const MAX: usize = 96;

/// Represents errors that can occur when constructing [`Count`] values.
///
/// This error is returned when the given value is less than [`MIN`] or greater than [`MAX`].
#[derive(Debug, Error)]
#[error("unexpected count `{value}`; expected in range `[{MIN}, {MAX}]`")]
pub struct Error {
    /// The unexpected value.
    pub value: usize,
}

impl Error {
    /// Constructs [`Self`]
    pub const fn new(value: usize) -> Self {
        Self { value }
    }
}

/// Represents sources of errors that can occur when parsing [`Count`] values.
#[derive(Debug, Error)]
#[cfg_attr(feature = "diagnostics", derive(Diagnostic))]
pub enum ParseError {
    /// Invalid count error.
    #[error("invalid count")]
    #[cfg_attr(
        feature = "diagnostics",
        diagnostic(
            code(pkce_std::count::parse),
            help("make sure the count is in the valid range")
        )
    )]
    Length(#[from] Error),
    /// Integer parse error.
    #[error("parse integer error")]
    #[cfg_attr(
        feature = "diagnostics",
        diagnostic(code(pkce_std::count::parse::int), help("check the string"))
    )]
    Int(#[from] ParseIntError),
}

/// Represents byte counts.
///
/// Refer to the [module] documentation for more information.
///
/// # Examples
///
/// ```
/// use pkce_std::count::Count;
///
/// let count = Count::new(64).unwrap();
///
/// assert_eq!(count.get(), 64);
/// ```
///
/// [module]: self
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Count {
    value: usize,
}

#[cfg(feature = "serde")]
impl Serialize for Count {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.get().serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Count {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = usize::deserialize(deserializer)?;

        Self::new(value).map_err(de::Error::custom)
    }
}

impl TryFrom<usize> for Count {
    type Error = Error;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Count> for usize {
    fn from(count: Count) -> Self {
        count.get()
    }
}

impl From<Count> for Length {
    fn from(count: Count) -> Self {
        // SAFETY: `bytes.encoded()` is in the valid range for `Self`
        unsafe { Self::new_unchecked(count.encoded()) }
    }
}

impl fmt::Display for Count {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(formatter)
    }
}

impl Default for Count {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl FromStr for Count {
    type Err = ParseError;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let value = string.parse()?;

        let count = Self::new(value)?;

        Ok(count)
    }
}

impl Count {
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
        const_early!(value < MIN || value > MAX => Error::new(value));

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

    /// Returns the encoded length corresponding to the byte count.
    pub const fn encoded(self) -> usize {
        encoding::length(self.get())
    }

    /// The minimum value of [`Self`].
    pub const MIN: Self = Self::new_ok(MIN).unwrap();

    /// The default value of [`Self`].
    pub const DEFAULT: Self = Self::new_ok(DEFAULT).unwrap();

    /// The maximum value of [`Self`].
    pub const MAX: Self = Self::new_ok(MAX).unwrap();
}
