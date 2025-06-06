//! PKCE code verifier lengths.
//!
//! As per the [standard](https://datatracker.ietf.org/doc/html/rfc7636#section-4.1), the length
//! of the code verifier must be at least `43` and at most `128`.
//!
//! This module provides the [`Length`] type, representing the actual length of the code verifier.
//!
//! The [`Length`] type internally stores [`usize`] values, which are guaranteed to be in the range
//! from [`MIN`] to [`MAX`] inclusively, defaulting to [`DEFAULT`].
//!
//! ```
//! use pkce_std::length::Length;
//!
//! let length = Length::new(128);
//! ```

use std::{fmt, num::ParseIntError, str::FromStr};

use const_macros::{const_early, const_ok, const_try};

#[cfg(feature = "diagnostics")]
use miette::Diagnostic;

#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use thiserror::Error;

use crate::{count, encoding};

/// The minimum length.
pub const MIN: usize = encoding::length(count::MIN);

/// The default length.
pub const DEFAULT: usize = encoding::length(count::DEFAULT);

/// The maximum length.
pub const MAX: usize = encoding::length(count::MAX);

/// Represents errors that can occur when constructing [`Length`] values.
///
/// This error is returned when the given value is less than [`MIN`] or greater than [`MAX`].
#[derive(Debug, Error)]
#[error("expected length in `[{MIN}, {MAX}]` range, got `{value}`")]
#[cfg_attr(
    feature = "diagnostics",
    derive(Diagnostic),
    diagnostic(
        code(pkce_std::length),
        help("make sure the length is at least `{MIN}` and at most `{MAX}`")
    )
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
#[derive(Debug, Error)]
#[cfg_attr(feature = "diagnostics", derive(Diagnostic))]
pub enum ParseError {
    /// Invalid length error.
    #[error("invalid length")]
    #[cfg_attr(
        feature = "diagnostics",
        diagnostic(
            code(pkce_std::length::parse),
            help("make sure the length is in the valid range")
        )
    )]
    Length(#[from] Error),
    /// Integer parse error.
    #[error("parse integer error")]
    #[cfg_attr(
        feature = "diagnostics",
        diagnostic(code(pkce_std::length::parse::int), help("check the string"))
    )]
    Int(#[from] ParseIntError),
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

impl fmt::Display for Length {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(formatter)
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

impl Default for Length {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl FromStr for Length {
    type Err = ParseError;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let value = string.parse()?;

        let length = Self::new(value)?;

        Ok(length)
    }
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

    /// The minimum value of [`Self`].
    pub const MIN: Self = Self::new_ok(MIN).unwrap();

    /// The default value of [`Self`].
    pub const DEFAULT: Self = Self::new_ok(DEFAULT).unwrap();

    /// The maximum value of [`Self`].
    pub const MAX: Self = Self::new_ok(MAX).unwrap();
}
