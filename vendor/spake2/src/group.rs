//! Local API declarations used by the vendored upstream implementation.
use alloc::vec::Vec;
use rand_core::{CryptoRng, RngCore};
use sha2::Digest;
/// Operations needed by SPAKE2. The supplied implementation is Ed25519Group.
pub trait Group {
    /// Scalar type.
    type Scalar: Eq;
    /// Group element type.
    type Element;
    /// Transcript hash.
    type TranscriptHash: Digest;
    /// Group name.
    fn name() -> &'static str;
    /// Fixed blinding point for role A.
    fn const_m() -> Self::Element;
    /// Fixed blinding point for role B.
    fn const_n() -> Self::Element;
    /// Fixed blinding point for symmetric mode.
    fn const_s() -> Self::Element;
    /// Map password bytes to a scalar.
    fn hash_to_scalar(bytes: &[u8]) -> Self::Scalar;
    /// Generate a scalar.
    fn random_scalar<T: CryptoRng + RngCore>(rng: &mut T) -> Self::Scalar;
    /// Negate a scalar.
    fn scalar_neg(scalar: &Self::Scalar) -> Self::Scalar;
    /// Encode an element.
    fn element_to_bytes(element: &Self::Element) -> Vec<u8>;
    /// Encoded element size.
    fn element_length() -> usize;
    /// Decode an element.
    fn bytes_to_element(bytes: &[u8]) -> Option<Self::Element>;
    /// Multiply the base point.
    fn basepoint_mult(scalar: &Self::Scalar) -> Self::Element;
    /// Multiply an arbitrary element.
    fn scalarmult(element: &Self::Element, scalar: &Self::Scalar) -> Self::Element;
    /// Add two elements.
    fn add(a: &Self::Element, b: &Self::Element) -> Self::Element;
}
