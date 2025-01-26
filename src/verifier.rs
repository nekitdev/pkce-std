//! PKCE code verifiers.
//!
//! The [`Verifier<'v>`] type represents PKCE code verifiers, which are strings
//! that consist of valid characters (see [`chars`]) and have certain lengths
//! (see [`length`]).
//!
//! # Examples
//!
//! Generating random verifiers:
//!
//! ```
//! use pkce_std::{length::Length, verifier::Verifier};
//!
//! let length = Length::default();
//!
//! let verifier = Verifier::generate(length);
//! let other = Verifier::generate(length);
//!
//! assert_ne!(verifier, other);
//! ```
//!
//! Generating verifiers from random bytes:
//!
//! ```
//! use pkce_std::{length::Bytes, verifier::Verifier};
//!
//! let bytes = Bytes::default();
//!
//! let verifier = Verifier::generate_encode(bytes);
//! let other = Verifier::generate_encode(bytes);
//!
//! assert_ne!(verifier, other);
//! ```
//!
//! [`Verifier<'v>`]: Verifier

use std::{
    borrow::Cow,
    fmt,
    hash::{Hash, Hasher},
};

use constant_time_eq::constant_time_eq;

use miette::Diagnostic;

#[cfg(feature = "serde")]
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use thiserror::Error;

use crate::{
    challenge::Challenge,
    chars, encoding, generate,
    length::{self, Bytes, BytesError, Length},
    method::Method,
};

/// Represents sources of errors that can occur when constructing verifiers.
#[derive(Debug, Error, Diagnostic)]
#[error(transparent)]
#[diagnostic(transparent)]
pub enum ErrorSource {
    /// Invalid length encountered.
    Length(#[from] length::Error),
    /// Invalid characters found.
    Chars(#[from] chars::Error),
}

/// Represents errors that can occur when constructing verifiers.
///
/// There are two cases when constructing can fail:
///
/// - [`Length::check`] fails, which means that the length of the string is invalid;
/// - [`chars::check`] fails, which means the string contains invalid characters.
#[derive(Debug, Error, Diagnostic)]
#[error("check failed")]
#[diagnostic(code(pkce_std::code), help("make sure the code is valid"))]
pub struct Error {
    /// The source of this error.
    #[source]
    #[diagnostic_source]
    pub source: ErrorSource,
}

impl Error {
    /// Constructs [`Self`].
    pub fn new(source: ErrorSource) -> Self {
        Self { source }
    }

    /// Constructs [`Self`] from [`length::Error`].
    pub fn length(error: length::Error) -> Self {
        Self::new(error.into())
    }

    /// Constructs [`Self`] from [`chars::Error`].
    pub fn chars(error: chars::Error) -> Self {
        Self::new(error.into())
    }
}

/// Represents PKCE code verifiers.
///
/// Refer to the [module] documentation for more information.
///
/// # Examples
///
/// ```
/// use pkce_std::verifier::Verifier;
///
/// let string = "dGhhbmtzIGZvciByZWFkaW5nIGRvY3MhIH4gbmVraXQ";
///
/// let expected = Verifier::borrowed(string).unwrap();
///
/// let bytes = "thanks for reading docs! ~ nekit";
///
/// let verifier = Verifier::encode(bytes).unwrap();
///
/// // `verifier` and `expected` are compared in constant time!
/// assert_eq!(verifier, expected);
/// ```
///
/// [module]: self
#[derive(Debug, Clone)]
pub struct Verifier<'v> {
    value: Cow<'v, str>,
}

#[cfg(feature = "serde")]
impl Serialize for Verifier<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.as_str().serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Verifier<'_> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Cow::deserialize(deserializer)?;

        Self::new(value).map_err(de::Error::custom)
    }
}

impl fmt::Display for Verifier<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(formatter)
    }
}

impl Verifier<'_> {
    /// Returns the borrowed string.
    pub fn as_str(&self) -> &str {
        self.value.as_ref()
    }
}

impl AsRef<str> for Verifier<'_> {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl PartialEq for Verifier<'_> {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(self.as_str().as_bytes(), other.as_str().as_bytes())
    }
}

impl Eq for Verifier<'_> {}

impl Hash for Verifier<'_> {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.as_str().hash(hasher);
    }
}

impl Verifier<'_> {
    /// Generates random [`Self`] with specified length.
    pub fn generate(length: Length) -> Self {
        // SAFETY: `generate::string(length)` creates valid values for `Self`,
        // meaning that their length is exactly `length` and they consist of valid characters.
        unsafe { Self::owned_unchecked(generate::string(length)) }
    }

    /// Generates `count` random bytes length and encodes them into [`Self`].
    pub fn generate_encode(count: Bytes) -> Self {
        // SAFETY: `generate::bytes(count)` creates valid values for `Self::encode_unchecked`,
        // meaning that their length is exactly `count`.
        unsafe { Self::encode_unchecked(generate::bytes(count)) }
    }
}

impl Verifier<'_> {
    /// Computes the [`Challenge`] of [`Self`] with the given [`Method`].
    pub fn challenge(&self, method: Method) -> Challenge {
        Challenge::create(self, method)
    }

    /// Computes the [`Challenge`] of [`Self`] with the default [`Method`].
    pub fn challenge_default(&self) -> Challenge {
        self.challenge(Method::default())
    }

    /// Verifies the given [`Challenge`] against [`Self`].
    pub fn verify(&self, challenge: &Challenge) -> bool {
        let expected = self.challenge(challenge.method());

        challenge == &expected
    }
}

impl<'v> Verifier<'v> {
    /// Constructs [`Self`], provided that the given value is valid.
    ///
    /// # Errors
    ///
    /// See [`Self::check`] for more information.
    pub fn new(value: Cow<'v, str>) -> Result<Self, Error> {
        Self::check(value.as_ref())?;

        // SAFETY: `value` consists of valid characters
        // and its length is in the valid range for `Self`
        Ok(unsafe { Self::new_unchecked(value) })
    }

    /// Constructs [`Self`] without checking the value.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `value` is valid for [`Self`].
    ///
    /// The value can be checked using [`Self::check`].
    pub const unsafe fn new_unchecked(value: Cow<'v, str>) -> Self {
        Self { value }
    }

    /// Constructs [`Self`] from borrowed `value`, provided it is valid.
    ///
    /// # Errors
    ///
    /// See [`Self::new`] for more information.
    pub fn borrowed(value: &'v str) -> Result<Self, Error> {
        Self::new(Cow::Borrowed(value))
    }

    /// Constructs [`Self`] from borrowed `value` without checking it.
    ///
    /// # Safety
    ///
    /// See [`Self::new_unchecked`] for more information.
    pub const unsafe fn borrowed_unchecked(value: &'v str) -> Self {
        // SAFETY: this function is `unsafe`, so the caller must ensure
        // that `value` is valid for `Self`
        unsafe { Self::new_unchecked(Cow::Borrowed(value)) }
    }

    /// Constructs [`Self`] from owned `value`, provided it is valid.
    ///
    /// # Errors
    ///
    /// See [`Self::new`] for more information.
    pub fn owned(value: String) -> Result<Self, Error> {
        Self::new(Cow::Owned(value))
    }

    /// Constructs [`Self`] from owned `value` without checking it.
    ///
    /// # Safety
    ///
    /// See [`Self::new_unchecked`] for more information.
    pub const unsafe fn owned_unchecked(value: String) -> Self {
        // SAFETY: this function is `unsafe`, so the caller must ensure
        // that `value` is valid for `Self`
        unsafe { Self::new_unchecked(Cow::Owned(value)) }
    }

    /// Checks if the given value is valid for [`Self`].
    ///
    /// # Errors
    ///
    /// Returns [`struct@Error`] if the value is invalid, which means either:
    ///
    /// - the length of the string is invalid (see [`Length::check`]);
    /// - the string contains invalid characters (see [`chars::check`]).
    pub fn check<S: AsRef<str>>(value: S) -> Result<(), Error> {
        fn check_inner(string: &str) -> Result<(), Error> {
            Length::check(string.len()).map_err(Error::length)?;

            chars::check(string).map_err(Error::chars)?;

            Ok(())
        }

        check_inner(value.as_ref())
    }

    /// Consumes [`Self`] and returns the contained string.
    pub fn get(self) -> Cow<'v, str> {
        self.value
    }
}

impl Verifier<'_> {
    /// Encodes the given `bytes` into [`Self`], provided `bytes` has valid length.
    ///
    /// # Errors
    ///
    /// Returns [`BytesError`] if the length of `bytes` is invalid.
    pub fn encode<B: AsRef<[u8]>>(bytes: B) -> Result<Self, BytesError> {
        Bytes::check(bytes.as_ref().len())?;

        // SAFETY: `bytes` has length in the valid range for `Self::encode_unchecked`
        Ok(unsafe { Self::encode_unchecked(bytes) })
    }

    /// Encodes the given `bytes` into [`Self`] without checking `bytes` length.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `bytes` has valid length.
    ///
    /// The `bytes` can be checked using [`Bytes::check`] on its length.
    pub unsafe fn encode_unchecked<B: AsRef<[u8]>>(bytes: B) -> Self {
        let string = encoding::encode(bytes);

        // SAFETY: this function is `unsafe`, so the caller must ensure that `bytes`
        // has length in the valid range for encoding, which produces valid values for `Self`
        unsafe { Self::owned_unchecked(string) }
    }
}

/// Represents owned PKCE code verifiers.
pub type Owned = Verifier<'static>;
