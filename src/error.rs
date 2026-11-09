//! Crate-wide error types.
//!
//! [`Error`] covers decoding and primitive-construction failures. Verification
//! failures use the richer [`VerificationError`](crate::verify::VerificationError)
//! defined in the `verify` module so callers can tell *why* a token was
//! rejected.

use core::fmt;

/// Result alias used throughout the crate for non-verification operations.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors raised while decoding wire formats or constructing primitives from
/// untrusted input.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A CBOR item was malformed, truncated, or not the expected type.
    Cbor(CborError),
    /// A value did not have the byte length required by its type.
    InvalidLength {
        /// What was being decoded.
        what: &'static str,
        /// Expected length (or minimum), in bytes.
        expected: usize,
        /// Actual length seen, in bytes.
        actual: usize,
    },
    /// A hash algorithm id was not recognised.
    UnknownHashAlgorithm(u16),
    /// A secp256k1 public key, signature, or recovery id was invalid.
    Crypto(&'static str),
    /// A numeric value fell outside its permitted range.
    OutOfRange(&'static str),
    /// A field held an unexpected discriminant (engine, predicate type, ...).
    UnexpectedValue(&'static str),
    /// A root trust base is structurally unsafe for quorum verification.
    InvalidTrustBase(&'static str),
}

/// Detailed CBOR decoding error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CborError {
    /// Ran out of bytes while reading an item.
    UnexpectedEof,
    /// The CBOR major type did not match what the decoder expected.
    UnexpectedMajorType {
        /// Major type the decoder required (0-7).
        expected: u8,
        /// Major type actually found.
        found: u8,
    },
    /// A definite-length array had a different element count than required.
    UnexpectedArrayLength {
        /// Required element count.
        expected: usize,
        /// Actual element count.
        found: usize,
    },
    /// Encountered a tag number other than the one required by a type.
    UnexpectedTag {
        /// Required tag number.
        expected: u64,
        /// Actual tag number.
        found: u64,
    },
    /// Additional-information field used a reserved/unsupported encoding
    /// (28-30) or an indefinite length (31), both rejected for determinism.
    UnsupportedAdditionalInfo(u8),
    /// Trailing bytes remained after a value that should have consumed all input.
    TrailingBytes,
    /// An integer did not fit into the target type.
    IntegerOverflow,
    /// A value or length used a wider-than-necessary CBOR encoding.
    NonCanonicalEncoding,
    /// Map keys were not in deterministic encoded-byte order.
    NonCanonicalMapOrder,
    /// A map contained the same encoded key more than once.
    DuplicateMapKey,
    /// An explicit decoder resource limit was exceeded.
    LimitExceeded(&'static str),
}

impl From<CborError> for Error {
    fn from(e: CborError) -> Self {
        Error::Cbor(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Cbor(e) => write!(f, "CBOR error: {e}"),
            Error::InvalidLength {
                what,
                expected,
                actual,
            } => write!(
                f,
                "invalid length for {what}: expected {expected}, got {actual}"
            ),
            Error::UnknownHashAlgorithm(id) => write!(f, "unknown hash algorithm id: {id}"),
            Error::Crypto(m) => write!(f, "crypto error: {m}"),
            Error::OutOfRange(m) => write!(f, "value out of range: {m}"),
            Error::UnexpectedValue(m) => write!(f, "unexpected value: {m}"),
            Error::InvalidTrustBase(m) => write!(f, "invalid root trust base: {m}"),
        }
    }
}

impl fmt::Display for CborError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CborError::UnexpectedEof => write!(f, "unexpected end of input"),
            CborError::UnexpectedMajorType { expected, found } => {
                write!(
                    f,
                    "unexpected major type: expected {expected}, found {found}"
                )
            }
            CborError::UnexpectedArrayLength { expected, found } => {
                write!(
                    f,
                    "unexpected array length: expected {expected}, found {found}"
                )
            }
            CborError::UnexpectedTag { expected, found } => {
                write!(f, "unexpected tag: expected {expected}, found {found}")
            }
            CborError::UnsupportedAdditionalInfo(i) => {
                write!(f, "unsupported additional information: {i}")
            }
            CborError::TrailingBytes => write!(f, "trailing bytes after value"),
            CborError::IntegerOverflow => write!(f, "integer overflow"),
            CborError::NonCanonicalEncoding => write!(f, "non-canonical CBOR encoding"),
            CborError::NonCanonicalMapOrder => {
                write!(f, "CBOR map keys are not in canonical order")
            }
            CborError::DuplicateMapKey => write!(f, "duplicate CBOR map key"),
            CborError::LimitExceeded(resource) => {
                write!(f, "CBOR resource limit exceeded: {resource}")
            }
        }
    }
}

impl core::error::Error for Error {}
impl core::error::Error for CborError {}
