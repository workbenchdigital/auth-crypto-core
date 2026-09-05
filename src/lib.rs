//! `auth-core` — plattformneutraler Kern von AUth.
//!
//! Enthält die Logik, die KEIN Dateisystem und KEINEN OS-Zugriff braucht und
//! daher zu WebAssembly kompilierbar ist: Krypto (Argon2id-KDF,
//! XChaCha20-Poly1305-AEAD) und — in Folgeschritten — TOTP, Vault-Format,
//! Importer und License-Verifikation.
//!
//! Ziel: Tauri-App und (künftig) Chrome-Extension teilen denselben Code, statt
//! zwei divergierende Krypto-Implementierungen zu pflegen.
//!
//! File-IO, OS-Bindungen (Windows Hello), IPC und App-Lifecycle bleiben bewusst
//! in der Tauri-App (`src-tauri`).

pub mod backup;
pub mod crypto;
pub mod error;
pub mod importers;
pub mod migration;
pub mod model;
pub mod totp;
pub mod vault;

pub use error::{CoreError, CoreResult};
