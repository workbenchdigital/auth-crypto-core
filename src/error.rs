//! Fehlertyp des plattformneutralen Kerns.
//!
//! Bewusst schlank und frei von Tauri-/IPC-Spezifika. Die Tauri-App mappt
//! `CoreError` an der Grenze auf ihren `AppError` (siehe
//! `src-tauri/src/error.rs`), sodass die IPC-Fehler-Semantik dort definiert
//! bleibt.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("Verschlüsselungsfehler: {0}")]
    Crypto(String),

    /// AEAD-Entschlüsselung fehlgeschlagen: falscher Schlüssel/Passwort,
    /// falsche AAD oder manipulierter Ciphertext. Bewusst ohne Detail, um
    /// kein Orakel zu bieten.
    #[error("Entschlüsselung fehlgeschlagen.")]
    DecryptFailed,

    #[error("Ungültige Eingabe: {0}")]
    InvalidInput(String),

    /// Der gespeicherte Vault-Body liess sich nicht lesen oder migrieren -
    /// unbekannte Schema-Version, kaputtes JSON, fehlgeschlagene
    /// Deserialisierung. Die App bildet das auf `AppError::VaultRead` ab und
    /// haelt damit den stabilen IPC-Fehlercode `vault_read` unveraendert.
    #[error("Vault konnte nicht gelesen werden: {0}")]
    VaultFormat(String),

    /// Ein `otpauth://`-URI liess sich nicht auswerten. Die App bildet das auf
    /// `AppError::InvalidOtpauth` ab (IPC-Code `invalid_otpauth`).
    #[error("Ungültiger otpauth-Link: {0}")]
    InvalidOtpauth(String),

    /// Ein Google-Authenticator-Migrations-Payload liess sich nicht auswerten.
    /// Die App bildet das auf `AppError::GoogleMigration` ab (IPC-Code
    /// `google_migration`).
    #[error("Google-Migration fehlgeschlagen: {0}")]
    GoogleMigration(String),

    /// Ein `.agbak`-Backup liess sich nicht oeffnen: falsches Magic/Version,
    /// kaputtes JSON, oder ein AEAD-Fehlschlag. Bewusst EIN Fehler fuer alle
    /// drei Faelle (B-123) - ein AEAD-Fehlschlag laesst sich ohnehin nicht
    /// zwischen "falsches Passwort" und "beschaedigte Datei" unterscheiden.
    /// Die App bildet das auf `AppError::BackupCorrupt` ab (IPC-Code
    /// `backup_corrupt`) - bewusst NICHT auf `InvalidPassword`, das waere
    /// der Vault-Text und suggerierte faelschlich, Master-Passwort oder
    /// Vault seien betroffen.
    #[error("Backup-Datei ist beschädigt oder das Passwort ist falsch.")]
    BackupCorrupt,

    /// Ein Aegis-JSON-Export liess sich nicht auswerten. Die App bildet das
    /// auf `AppError::AegisImport` ab (IPC-Code `aegis_import`).
    #[error("Aegis-Import: {0}")]
    AegisImport(String),

    /// Ein 2FAS-JSON-Export liess sich nicht auswerten. Die App bildet das
    /// auf `AppError::TwoFasImport` ab (IPC-Code `twofas_import`).
    #[error("2FAS-Import: {0}")]
    TwoFasImport(String),
}

impl CoreError {
    /// Spiegelt die Ergonomie von `AppError::invalid_input` in der App: Die
    /// Aufrufstellen uebergeben `&str` genauso wie `String`, ohne an jeder
    /// Stelle ein `.into()` mitzuschleppen.
    pub fn invalid_input<S: Into<String>>(msg: S) -> Self {
        Self::InvalidInput(msg.into())
    }
}

pub type CoreResult<T> = Result<T, CoreError>;
