//! PKCE code challenges.
//!
//! [`Challenge`] is computed from the given string using the specified method:
//!
//! - [`Method::Plain`] uses the string as-is.
//! - [`Method::Sha256`] hashes the string with SHA-256 and encodes the result.
//!
//! The string usually comes from the [`Verifier`], which creates the appropriate
//! [`Challenge`] using the [`challenge`] method.
//!
//! [`challenge`]: Verifier::challenge

use std::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{encoding::encode, hash::hash, method::Method, verifier::Verifier};

/// Represents PKCE code challenges.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Challenge {
    secret: String,
    method: Method,
}

/// Represents PKCE code challenge parts.
pub type Parts = (String, Method);

impl fmt::Display for Challenge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.secret().fmt(formatter)
    }
}

impl Challenge {
    /// Returns the borrowed secret.
    pub fn secret(&self) -> &str {
        self.secret.as_str()
    }

    /// Returns the method used to generate the challenge.
    pub const fn method(&self) -> Method {
        self.method
    }

    /// Consumes [`Self`] and returns its `(secret, method)` parts.
    pub fn into_parts(self) -> Parts {
        (self.secret, self.method)
    }
}

impl From<Challenge> for Parts {
    fn from(challenge: Challenge) -> Self {
        challenge.into_parts()
    }
}

impl Challenge {
    const fn new(secret: String, method: Method) -> Self {
        Self { secret, method }
    }
}

impl Challenge {
    /// Creates code challenges from the given verifier using the given method.
    pub fn create_using(method: Method, verifier: &Verifier<'_>) -> Self {
        let string = verifier.as_str();

        let secret = match method {
            Method::Plain => string.to_owned(),
            Method::Sha256 => encode(hash(string)),
        };

        Self::new(secret, method)
    }

    /// Creates code challenges from the given verifier using the default method.
    pub fn create(verifier: &Verifier<'_>) -> Self {
        Self::create_using(Method::default(), verifier)
    }
}
