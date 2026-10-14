# Source provenance and local changes

This directory contains RustCrypto SPAKE2 0.4.0, originally by Brian Warner and
RustCrypto contributors, used under Apache-2.0 (see LICENSE-APACHE).

The algorithm files `src/lib.rs` and `src/ed25519.rs` were obtained from the
upstream `spake2-v0.4.0` tag through the source-reading tool because the build
sandbox could not resolve crates.io. Source line coverage was checked before
writing these files:

- https://github.com/RustCrypto/PAKEs/blob/spake2-v0.4.0/spake2/src/lib.rs
- https://github.com/RustCrypto/PAKEs/blob/spake2-v0.4.0/spake2/src/ed25519.rs
- https://github.com/RustCrypto/PAKEs/blob/spake2-v0.4.0/spake2/Cargo.toml

Local adaptations (this is NOT a byte-identical crates.io package):

- `src/group.rs` and `src/error.rs` are locally written trait/error declarations
  matching the operations required by the upstream implementation; these files
  could not be retrieved from the source service. They contain no curve or
  password-exchange arithmetic.
- Cargo uses the locally cached `sha2 0.11` and `hkdf 0.13` in place of upstream
  `sha2 0.10` / `hkdf 0.12`; the upstream password-to-scalar, transcript, and
  asymmetric exchange vectors were retained and passed.
- Benchmark dependencies and target were omitted. README is a local provenance
  summary; the standard Apache-2.0 license text is included.
- Cayman validates canonical, non-small-order, torsion-free peer points before
  calling the upstream `finish`, and adds domain/role/room-bound confirmation.

Validation:

```sh
cargo test --offline --manifest-path vendor/spake2/Cargo.toml --features std
```

The 8 upstream unit tests and 4 documentation tests passed. This and Cayman
protocol tests are not an independent security audit. The upstream library
itself states it has not received an independent third-party audit. Once normal
registry access is available, this local package should be reviewed against the
published release before replacing it with a registry dependency; keep the
compatibility vectors and input validation.
