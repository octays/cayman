//! SPAKE2 bootstrap, key schedule, and authenticated record layer.
//! Never derive these keys directly from a human password.
pub mod direct;
mod record;
pub use record::{CryptoError, Direction, KeySchedule, Opener, Sealer};
pub mod pairing;
