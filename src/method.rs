//! PKCE code challenge methods.
//!
//! As per the [standard](https://datatracker.ietf.org/doc/html/rfc7636#section-4.2),
//! there are two methods: plain and SHA-256.
//!
//! The former is discouraged and is only used as the last resort,
//! while the latter is recommended and is marked as the default.
//!
//! # Examples
//!
//! ```
//! use pkce_std::method::Method;
//!
//! let string = "S256";
//!
//! let method: Method = string.parse().unwrap();
//!
//! assert_eq!(method, Method::Sha256);
//! ```

use std::str::FromStr;

#[cfg(feature = "diagnostics")]
use miette::Diagnostic;

#[cfg(feature = "serde")]
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use thiserror::Error;

/// Represents errors that can occur when parsing PKCE methods.
#[derive(Debug, Error)]
#[error("unknown method `{unknown}`")]
#[cfg_attr(
    feature = "diagnostics",
    derive(Diagnostic),
    diagnostic(
        code(pkce_std::method),
        help("expected either `{PLAIN}` (discouraged) or `{SHA256}` (recommended)")
    )
)]
pub struct Error {
    /// The unknown method.
    pub unknown: String,
}

impl Error {
    /// Constructs [`Self`].
    pub const fn new(unknown: String) -> Self {
        Self { unknown }
    }
}

/// The `plain` literal.
pub const PLAIN: &str = "plain";

/// The `S256` literal.
pub const SHA256: &str = "S256";

/// Represents PKCE code challenge methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Method {
    /// The plain method, which is discouraged and only used as the last resort.
    Plain,
    /// The SHA-256 method, which is recommended and marked as the default.
    #[default]
    Sha256,
}

#[cfg(feature = "serde")]
impl Serialize for Method {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.static_str().serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Method {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let string = <&str>::deserialize(deserializer)?;

        string.parse().map_err(de::Error::custom)
    }
}

type StaticStr = &'static str;

impl Method {
    /// Returns the static string representation of the method.
    pub const fn static_str(&self) -> StaticStr {
        match self {
            Self::Plain => PLAIN,
            Self::Sha256 => SHA256,
        }
    }
}

impl FromStr for Method {
    type Err = Error;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        match string {
            PLAIN => Ok(Self::Plain),
            SHA256 => Ok(Self::Sha256),
            _ => Err(Self::Err::new(string.to_owned())),
        }
    }
}
