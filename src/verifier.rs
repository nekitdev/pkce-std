//! PKCE code verifiers.
//!
//! The [`Verifier<'_>`] type represents PKCE code verifiers, which are strings
//! that consist of valid characters (see [`string`]) and have certain lengths
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
//! use pkce_std::{count::Count, verifier::Verifier};
//!
//! let count = Count::default();
//!
//! let verifier = Verifier::generate_encode(count);
//! let other = Verifier::generate_encode(count);
//!
//! assert_ne!(verifier, other);
//! ```
//!
//! [`Verifier<'_>`]: Verifier

use std::{
    borrow::Cow,
    fmt,
    hash::{Hash, Hasher},
};

use const_macros::{const_map_err, const_none, const_ok, const_try};
use constant_time_eq::constant_time_eq;

#[cfg(feature = "static")]
use into_static::IntoStatic;

#[cfg(feature = "diagnostics")]
use miette::Diagnostic;

#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use thiserror::Error;

use crate::{
    challenge::Challenge,
    check::string::{self, const_check_str},
    count::{self, Count},
    encoding, generate,
    length::{self, Length},
    method::Method,
};

/// Represents the error message for invalid verifiers.
pub const ERROR: &str = "invalid verifier; check the length and characters";

/// Represents errors that can occur when constructing verifiers.
///
/// There are two cases when constructing can fail:
///
/// - [`Length::check`] fails, which means that the length of the string is invalid;
/// - [`string::check`] fails, which means the string contains invalid characters.
#[derive(Debug, Error)]
#[cfg_attr(feature = "diagnostics", derive(Diagnostic))]
pub enum Error {
    /// Invalid verifier length.
    #[error("invalid verifier length")]
    #[cfg_attr(
        feature = "diagnostics",
        diagnostic(
            code(pkce_std::verifier::length),
            help("check the length of the verifier")
        )
    )]
    Length(#[from] length::Error),

    /// Invalid character(s) in verifier.
    #[error("verifier contains invalid character(s)")]
    #[cfg_attr(
        feature = "diagnostics",
        diagnostic(
            code(pkce_std::verifier::check),
            help("make sure the verifier is composed of valid characters only")
        )
    )]
    String(#[from] string::Error),
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
        self.get().serialize(serializer)
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
        self.get().fmt(formatter)
    }
}

impl Verifier<'_> {
    /// Returns the borrowed string.
    pub fn get(&self) -> &str {
        self.value.as_ref()
    }
}

impl AsRef<str> for Verifier<'_> {
    fn as_ref(&self) -> &str {
        self.get()
    }
}

impl PartialEq for Verifier<'_> {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(self.get().as_bytes(), other.get().as_bytes())
    }
}

impl Eq for Verifier<'_> {}

impl Hash for Verifier<'_> {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.get().hash(hasher);
    }
}

impl Verifier<'_> {
    /// Generates random [`Self`] with specified length.
    pub fn generate(length: Length) -> Self {
        // SAFETY: `generate::string(length)` creates valid values for `Self`,
        // meaning that their length is exactly `length` and they consist of valid characters.
        unsafe { Self::owned_unchecked(generate::string(length)) }
    }

    /// Generates random [`Self`] with default length.
    pub fn generate_default() -> Self {
        Self::generate(Length::default())
    }

    /// Generates `count` random bytes length and encodes them into [`Self`].
    pub fn generate_encode(count: Count) -> Self {
        // SAFETY: `generate::bytes(count)` creates valid values for `Self::encode_unchecked`,
        // meaning that their length is exactly `count`.
        unsafe { Self::encode_unchecked(generate::bytes(count)) }
    }

    /// Generates random bytes of default length and encodes them into [`Self`].
    pub fn generate_encode_default() -> Self {
        Self::generate_encode(Count::default())
    }
}

impl Verifier<'_> {
    /// Computes the [`Challenge`] of [`Self`] with the given [`Method`].
    pub fn challenge_using(&self, method: Method) -> Challenge {
        Challenge::create_using(method, self)
    }

    /// Computes the [`Challenge`] of [`Self`] with the default [`Method`].
    pub fn challenge(&self) -> Challenge {
        self.challenge_using(Method::default())
    }

    /// Verifies the given [`Challenge`] against [`Self`].
    pub fn verify(&self, challenge: &Challenge) -> bool {
        let expected = self.challenge_using(challenge.method());

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

    /// Similar to [`borrowed`], but can be used in `const` contexts.
    ///
    /// # Note
    ///
    /// One may need to increase the recursion limit when using longer strings.
    ///
    /// This is done via applying the `recursion_limit` attribute to the crate:
    ///
    /// ```
    /// #![recursion_limit = "256"]
    /// ```
    ///
    /// # Errors
    ///
    /// See [`const_check_str`] for more information.
    ///
    /// [`borrowed`]: Self::borrowed
    /// [`const_check_str`]: Self::const_check_str
    pub const fn const_borrowed(value: &'v str) -> Result<Self, Error> {
        const_try!(Self::const_check_str(value));

        // SAFETY: `value` is valid for `Self` here
        Ok(unsafe { Self::borrowed_unchecked(value) })
    }

    /// Similar to [`const_borrowed`], but errors are discarded.
    ///
    /// [`const_borrowed`]: Self::const_borrowed
    pub const fn const_borrowed_ok(value: &'v str) -> Option<Self> {
        const_none!(const_ok!(Self::const_check_str(value)));

        // SAFETY: `value` is valid for `Self` here
        Some(unsafe { Self::borrowed_unchecked(value) })
    }

    /// Constantly checks if the given string is valid for [`Self`].
    ///
    /// # Note
    ///
    /// One may need to increase the recursion limit when checking longer strings.
    ///
    /// This is done via applying the `recursion_limit` attribute to the crate:
    ///
    /// ```
    /// #![recursion_limit = "256"]
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`enum@Error`] if the string is invalid, which means either:
    ///
    /// - the length of the string is invalid (see [`Length::check`]);
    /// - the string contains invalid character(s) (see [`string::check`]).
    pub const fn const_check_str(string: &str) -> Result<(), Error> {
        const_try!(const_map_err!(Length::check(string.len()) => Error::Length));

        const_try!(const_map_err!(const_check_str(string) => Error::String));

        Ok(())
    }

    /// Checks if the given string is valid for [`Self`].
    ///
    /// # Errors
    ///
    /// Returns [`enum@Error`] if the string is invalid, which means either:
    ///
    /// - the length of the string is invalid (see [`Length::check`]);
    /// - the string contains invalid character(s) (see [`string::check`]).
    pub fn check_str(string: &str) -> Result<(), Error> {
        Length::check(string.len())?;

        string::check_str(string)?;

        Ok(())
    }

    /// Similar to [`check_str`], except it is generic over [`AsRef<str>`].
    ///
    /// # Errors
    ///
    /// Any [`enum@Error`] returned by [`check_str`] is propagated.
    ///
    /// [`check_str`]: Self::check_str
    pub fn check<S: AsRef<str>>(value: S) -> Result<(), Error> {
        Self::check_str(value.as_ref())
    }

    /// Consumes [`Self`] and returns the contained string.
    pub fn take(self) -> Cow<'v, str> {
        self.value
    }
}

impl Verifier<'_> {
    /// Encodes the given `bytes` into [`Self`], provided `bytes` has valid length.
    ///
    /// # Errors
    ///
    /// Returns [`count::Error`] if the length of `bytes` is invalid.
    pub fn encode<B: AsRef<[u8]>>(bytes: B) -> Result<Self, count::Error> {
        Count::check(bytes.as_ref().len())?;

        // SAFETY: `bytes` has length in the valid range for `Self::encode_unchecked`
        Ok(unsafe { Self::encode_unchecked(bytes) })
    }

    /// Encodes the given `bytes` into [`Self`] without checking `bytes` length.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `bytes` has valid length.
    ///
    /// The `bytes` can be checked using [`Count::check`] on its length.
    pub unsafe fn encode_unchecked<B: AsRef<[u8]>>(bytes: B) -> Self {
        let string = encoding::encode(bytes);

        // SAFETY: this function is `unsafe`, so the caller must ensure that `bytes`
        // has length in the valid range for encoding, which produces valid values for `Self`
        unsafe { Self::owned_unchecked(string) }
    }
}

/// Constructs [`Verifier`] from `value`, panicking if it is invalid.
#[macro_export]
macro_rules! const_borrowed_verifier {
    ($value: expr) => {
        $crate::verifier::Verifier::const_borrowed_ok($value).expect($crate::verifier::ERROR)
    };
}

/// An alias for [`Verifier<'static>`].
#[cfg(feature = "static")]
pub type StaticVerifier = Verifier<'static>;

#[cfg(feature = "static")]
impl IntoStatic for Verifier<'_> {
    type Static = StaticVerifier;

    fn into_static(self) -> Self::Static {
        // SAFETY: calling `into_static` does not change `value` validity
        unsafe { Self::Static::new_unchecked(self.value.into_static()) }
    }
}
