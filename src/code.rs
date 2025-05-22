//! Coupled PKCE code verifier and challenge pairs.
//!
//! The [`Code`] type provides ergonomic and simple methods to generate verifier-challenge pairs.
//!
//! [`Code`] is slightly more than simply using [`Verifier`] and [`Challenge`] together, as it
//! imposes the following invariant: the verifier and challenge are always generated together and
//! the challenge corresponds to the verifier, meaning `verifier.verify(&challenge)` is always true.
//!
//! Therefore it is not possible to access the verifier or challenge separately, and one should use
//! [`into_pair`] to get both parts, consuming the [`Code`] value.
//!
//! # Examples
//!
//! ```
//! use pkce_std::code::Code;
//!
//! let code = Code::generate_default();
//!
//! let (verifier, challenge) = code.into_pair();
//!
//! // this is always true here!
//! assert!(verifier.verify(&challenge));
//! ```
//!
//! [`into_pair`]: Code::into_pair

use std::borrow::Cow;

#[cfg(feature = "static")]
use into_static::IntoStatic;

use crate::{
    challenge::Challenge, count::Count, length::Length, method::Method, verifier::Verifier,
};

/// Represents coupled [`Verifier`] and [`Challenge`] pairs.
///
/// Refer to the [module] documentation for more information.
///
/// [module]: self
#[derive(Debug, Clone)]
pub struct Code<'c> {
    verifier: Verifier<'c>,
    challenge: Challenge,
}

impl<'c> Code<'c> {
    const fn new(verifier: Verifier<'c>, challenge: Challenge) -> Self {
        Self {
            verifier,
            challenge,
        }
    }

    /// Consumes [`Self`], returning the `(verifier, challenge)` pair.
    pub fn into_pair(self) -> Pair<'c> {
        (self.verifier, self.challenge)
    }

    /// Consumes [`Self`], returning `(verifier, secret, method)` parts.
    pub fn into_parts(self) -> Parts<'c> {
        let (secret, method) = self.challenge.into_parts();

        (self.verifier.take(), secret, method)
    }
}

impl Code<'_> {
    /// Generates [`Self`] using the given method and length.
    pub fn generate_using(method: Method, length: Length) -> Self {
        let verifier = Verifier::generate(length);
        let challenge = verifier.challenge_using(method);

        Self::new(verifier, challenge)
    }

    /// Generates [`Self`] using the default method and the given length.
    pub fn generate(length: Length) -> Self {
        Self::generate_using(Method::default(), length)
    }

    /// Generates [`Self`] using the default method and length.
    pub fn generate_default() -> Self {
        Self::generate(Length::default())
    }

    /// Generates [`Self`] using the given method and bytes count.
    pub fn generate_encode_using(method: Method, count: Count) -> Self {
        let verifier = Verifier::generate_encode(count);
        let challenge = verifier.challenge_using(method);

        Self::new(verifier, challenge)
    }

    /// Generates [`Self`] using the default method and the given bytes count.
    pub fn generate_encode(count: Count) -> Self {
        Self::generate_encode_using(Method::default(), count)
    }

    /// Generates [`Self`] using the default method and bytes count.
    pub fn generate_encode_default() -> Self {
        Self::generate_encode(Count::default())
    }
}

/// An alias for [`Code<'static>`].
#[cfg(feature = "static")]
pub type StaticCode = Code<'static>;

#[cfg(feature = "static")]
impl IntoStatic for Code<'_> {
    type Static = StaticCode;

    fn into_static(self) -> Self::Static {
        Self::Static::new(self.verifier.into_static(), self.challenge)
    }
}

/// Represents `(verifier, challenge)` pairs.
pub type Pair<'p> = (Verifier<'p>, Challenge);

/// Represents owned [`Pair`] values.
pub type OwnedPair = Pair<'static>;

impl<'c> From<Code<'c>> for Pair<'c> {
    fn from(code: Code<'c>) -> Self {
        code.into_pair()
    }
}

/// Represents `(verifier, secret, method)` parts.
pub type Parts<'p> = (Cow<'p, str>, String, Method);

/// Represents owned [`Parts`] values.
pub type OwnedParts = Parts<'static>;

impl<'c> From<Code<'c>> for Parts<'c> {
    fn from(code: Code<'c>) -> Self {
        code.into_parts()
    }
}
