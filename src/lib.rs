//! Handling Proof Key for Code Exchange.
//!
//! PKCE specification is defined in [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636).
//!
//! # Abstract
//!
//! PKCE (pronounced "pixy") is a method to secure authorization codes in OAuth 2.0
//! *authorization code* flow. It is designed to prevent interception attacks.
//!
//! # Abbreviations
//!
//! - `PKCE`: Proof Key for Code Exchange;
//! - `Auth`: Authorization.
//!
//! # Protocol
//!
//! ```text
//!                                                   +--------------+
//!                                                   |     Auth     |
//! +--------+                                        | +----------+ |
//! |        |--(1)- Auth Request + code_challenge ---->|          | |
//! |        |         + code_challenge_method        | |   Auth   | |
//! |        |                                        | | Endpoint | |
//! |        |<-(2)----------- Auth Code ---------------|          | |
//! |        |                                        | +----------+ |
//! | Client |                                        |              |
//! |        |                                        | +----------+ |
//! |        |--(3)- Token Request + code_verifier ---->|          | |
//! |        |                                        | |  Tokens  | |
//! |        |                                        | | Endpoint | |
//! |        |<-(4)------------- Token -----------------|          | |
//! +--------+                                        | +----------+ |
//!                                                   |    Server    |
//!                                                   +--------------+
//! ```
//!
//! ## 0. Code creation
//!
//! The *client* generates the `code_verifier` and derives the `code_challenge` from it
//! using the `code_challenge_method`.
//!
//! ## 1. Auth Request
//!
//! The *client* sends the `code_challenge` and the `code_challenge_method` along with the
//! regular `authorization_code` request to the *Auth Endpoint*.
//!
//! ## 2. Auth Code
//!
//! The *server* stores the `code_challenge` and the `code_challenge_method` for later use,
//! responding with the usual authorization `code`.
//!
//! ## 3. Token Request
//!
//! The *client* sends the `code_verifier` along with the regular request to the *Tokens Endpoint*.
//!
//! ## 4. Token
//!
//! The *server* verifies the `code_verifier` against the stored `code_challenge` using the
//! `code_challenge_method`, responding with the `token` if the verification is successful.
//!
//! # Examples
//!
//! Generating `code_verifier` and deriving `code_challenge` in one go:
//!
//! ```
//! use pkce_std::Code;
//!
//! let code = Code::generate_default();
//! ```
//!
//! Alternatively, generating from random bytes:
//!
//! ```
//! use pkce_std::Code;
//!
//! let code = Code::generate_encode_default();
//! ```
//!
//! Decoupling verifier and challenge:
//!
//! ```
//! # use pkce_std::Code;
//! #
//! # let code = Code::generate_default();
//! #
//! let (verifier, challenge) = code.into_pair();
//! ```
//!
//! Verifying `code_verifier` against `code_challenge`:
//!
//! ```
//! # use pkce_std::Code;
//! #
//! # let (verifier, challenge) = Code::generate_default().into_pair();
//! #
//! let valid = verifier.verify(&challenge);
//! ```

#![warn(missing_docs)]

pub mod challenge;
pub mod chars;
pub mod code;
pub mod encoding;
pub mod generate;
pub mod hash;
pub mod int;
pub mod length;
pub mod method;
pub mod verifier;

pub use challenge::Challenge;
pub use chars::CHARS;
pub use code::{Code, Pair};
pub use length::{Bytes, Length};
pub use method::Method;
pub use verifier::Verifier;
