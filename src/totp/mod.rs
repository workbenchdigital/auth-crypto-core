//! TOTP-Berechnung (RFC 6238) – plattformneutral und zeit-quellen-frei.

pub mod engine;

pub use engine::{generate_totp, TotpCode, TotpParams};
