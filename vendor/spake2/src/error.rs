//! Local error declarations used by the vendored upstream implementation.
use core::fmt;
/// Invalid SPAKE2 peer message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Incorrect message size.
    WrongLength,
    /// Incorrect participant role.
    BadSide,
    /// Invalid encoded group element.
    CorruptMessage,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "invalid SPAKE2 message: {self:?}") }
}
#[cfg(feature = "std")]
impl std::error::Error for Error {}
/// SPAKE2 result.
pub type Result<T> = core::result::Result<T, Error>;
