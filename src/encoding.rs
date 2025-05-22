//! Encoding functionality.
//!
//! This module provides functions to encode data to Base64.
//!
//! There are also [`try_length`] and [`length`] functions to calculate the
//! length of the encoded data.
//!
//! # Examples
//!
//! ```
//! use pkce_std::encoding::{encode, length};
//!
//! let data = "Hello, world!";
//!
//! let encoded = encode(data);
//!
//! assert_eq!(encoded.len(), length(data.len()));
//! ```

use base64::engine::{general_purpose::URL_SAFE_NO_PAD, Engine};

/// Encodes given data into Base64.
///
/// This function uses the URL-safe and no-padding variant of Base64.
///
/// # Examples
///
/// ```
/// use pkce_std::encoding::encode;
///
/// let data = "Hello, world!";
///
/// assert_eq!(encode(data), "SGVsbG8sIHdvcmxkIQ");
/// ```
pub fn encode<D: AsRef<[u8]>>(data: D) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Computes the length of the Base64 encoded data from the given length.
///
/// # Examples
///
/// ```
/// use pkce_std::encoding::try_length;
///
/// assert_eq!(try_length(32), Some(43));
///
/// assert_eq!(try_length(usize::MAX), None);
/// ```
pub const fn try_length(bytes: usize) -> Option<usize> {
    let remainder = bytes % 3;
    let chunks = bytes / 3;

    let Some(length) = chunks.checked_mul(4) else {
        return None;
    };

    if remainder == 0 {
        Some(length)
    } else {
        length.checked_add(remainder + 1)
    }
}

/// The `overflow` literal.
pub const OVERFLOW: &str = "overflow";

/// Calls [`try_length`] and panics if the result is [`None`].
///
/// The only reason for this function to panic is an overflow.
///
/// # Panics
///
/// This function panics if the result of [`try_length`] is [`None`].
///
/// # Examples
///
/// Regular usage:
///
/// ```
/// use pkce_std::encoding::length;
///
/// assert_eq!(length(96), 128);
/// ```
///
/// Overflow:
///
/// ```should_panic
/// use pkce_std::encoding::length;
///
/// length(usize::MAX);
/// ```
pub const fn length(bytes: usize) -> usize {
    try_length(bytes).expect(OVERFLOW)
}
