//! Integer parsing errors.
//!
//! The only type in this module is [`ParseError`], which wraps [`ParseIntError`]
//! to provide diagnostics.

use std::num::ParseIntError;

use miette::Diagnostic;
use thiserror::Error;

/// Wraps [`ParseIntError`] to provide diagnostics.
#[derive(Debug, Error, Diagnostic)]
#[error("failed to parse integer")]
#[diagnostic(code(pkce_std::int::parse), help("ensure the input is valid"))]
pub struct ParseError(#[from] pub ParseIntError);
