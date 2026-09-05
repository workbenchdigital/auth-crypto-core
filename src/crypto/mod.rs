//! Krypto-Kern: Argon2id-KDF + XChaCha20-Poly1305-AEAD.
//!
//! Sicherheits-Kontrakte:
//! - `kdf`: Argon2id mit OWASP-2026-Parametern (m = 64 MiB, t = 3, p = 4) → 32-Byte-KEK.
//! - `aead`: XChaCha20-Poly1305 mit zufälliger 24-Byte-Nonce. Die AAD ist ein
//!   statisches Domänen-Label und leistet **Domain-Separation** (ein für eine
//!   Domäne versiegelter Ciphertext ist in einer anderen nicht entschlüsselbar).
//!   Sie bindet NICHT an eine konkrete Instanz (kein Salt/keine ID).
//!
//! Alle Klartext-Schlüssel nutzen `Zeroizing`, um sie beim Drop aus dem RAM zu löschen.

pub mod aead;
pub mod kdf;

pub use aead::{aead_open, aead_seal, AeadCiphertext, AEAD_KEY_LEN, AEAD_NONCE_LEN};
pub use kdf::{
    derive_key, derive_key_legacy_unnormalised, is_password_nfc, KdfParams, KEY_LEN, SALT_LEN,
};
