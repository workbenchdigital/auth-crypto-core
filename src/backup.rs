//! Verschlüsseltes Backup-Format `.agbak` — der Umschlag selbst.
//!
//! O-3 Schritt 3 (letzter Teil). Reine Bytes-zu-Bytes-Logik: Passwort → KEK,
//! Payload versiegeln/öffnen. Kein Dateisystem, kein Pfad — das Lesen und
//! Schreiben der Datei bleibt in `src-tauri/src/exporters/backup.rs`.
//!
//! Spiegelt exakt den Schnitt aus [`crate::vault`] (O-3 Schritt 3d): Format
//! hier, IO dort — aus demselben Grund (WASM-Fähigkeit, eine geteilte
//! Implementierung statt zweier, die auseinanderlaufen können).
//!
//! Datei-Layout (JSON, identifizierbar am Magic-Wert):
//! ```json
//! {
//!   "magic": "AGBK",
//!   "version": 1,
//!   "kdf": { "m_cost": 65536, "t_cost": 3, "p_cost": 4 },
//!   "salt": "<base64>",
//!   "ct": { "nonce": "...", "ct": "..." }   // KEK -> JSON(accounts+settings)
//! }
//! ```
//!
//! **Formatkompatibilität ist eine harte Grenze** — wie beim Vault-Format,
//! nur mit höherem Einsatz: ein `.agbak` ist laut `docs/PILOT.md` oft der
//! einzige Weg zurück, wenn Vault oder Master-Passwort verloren sind. Der
//! Golden-Backup-Test in diesem Modul sichert das ab.

use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{
    aead_open, aead_seal, derive_key, derive_key_legacy_unnormalised, is_password_nfc,
    AeadCiphertext, KdfParams, SALT_LEN,
};
use crate::error::{CoreError, CoreResult};
use crate::model::{Account, VaultSettings};
use crate::vault::MIN_MASTER_PASSWORD_CHARS;

pub const BACKUP_MAGIC: &str = "AGBK";
pub const BACKUP_VERSION: u8 = 1;

#[derive(Debug, Serialize, Deserialize)]
struct BackupFile {
    magic: String,
    version: u8,
    kdf: KdfParams,
    salt: String,
    ct: AeadCiphertext,
}

#[derive(Debug, Serialize, Deserialize)]
struct BackupPayload {
    accounts: Vec<Account>,
    settings: VaultSettings,
    exported_at: String,
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
}

fn encode(b: &[u8]) -> String {
    use base64::Engine;
    b64().encode(b)
}

fn decode(s: &str) -> CoreResult<Vec<u8>> {
    use base64::Engine;
    b64().decode(s.as_bytes()).map_err(|e| {
        tracing::warn!("Backup base64-Decode fehlgeschlagen: {e}");
        CoreError::BackupCorrupt
    })
}

/// Versiegelt Konten und Einstellungen zu den fertigen Bytes einer
/// `.agbak`-Datei (druckfertiges JSON).
///
/// B-132: dieselbe Mindestlängen-Policy wie beim Master-Passwort
/// (`vault::MIN_MASTER_PASSWORD_CHARS`), hier aber ohne Legacy-
/// Bestandsschutz — jedes Backup wird neu geschrieben.
pub fn seal_backup(
    password: &str,
    accounts: &[Account],
    settings: &VaultSettings,
) -> CoreResult<Vec<u8>> {
    if password.chars().count() < MIN_MASTER_PASSWORD_CHARS {
        return Err(CoreError::invalid_input(format!(
            "Backup-Passwort muss mindestens {MIN_MASTER_PASSWORD_CHARS} Zeichen lang sein"
        )));
    }
    let kdf = KdfParams::default();
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let key = derive_key(password, &salt, kdf)?;

    let payload = BackupPayload {
        accounts: accounts.to_vec(),
        settings: settings.clone(),
        exported_at: chrono::Utc::now().to_rfc3339(),
    };
    // B-104: wie bei reseal_body enthaelt dieses JSON alle Secrets im
    // Klartext, hier zusaetzlich noch die Settings - nach dem Versiegeln
    // aktiv ueberschreiben statt nur freigeben.
    let raw = Zeroizing::new(
        serde_json::to_vec(&payload)
            .map_err(|e| CoreError::Crypto(format!("Payload-Serialisierung: {e}")))?,
    );
    let ct = aead_seal(key.as_slice(), &raw, b"agbak-payload-v1")?;

    let file = BackupFile {
        magic: BACKUP_MAGIC.into(),
        version: BACKUP_VERSION,
        kdf,
        salt: encode(&salt),
        ct,
    };
    serde_json::to_vec_pretty(&file)
        .map_err(|e| CoreError::Crypto(format!("Umschlag-Serialisierung: {e}")))
}

/// Entsiegelt die Bytes einer `.agbak`-Datei.
///
/// B-106: derselbe Legacy-Fallback wie beim Vault-Unlock. Ein `.agbak`, das
/// vor dem Fix mit einem Nicht-ASCII-Passwort exportiert wurde, haette sich
/// sonst nie wieder importieren lassen - bei einem Backup, das genau fuer
/// den Ernstfall existiert, waere das der denkbar schlechteste Zeitpunkt
/// fuer eine Inkompatibilitaet.
pub fn open_backup(raw: &[u8], password: &str) -> CoreResult<(Vec<Account>, VaultSettings, String)> {
    let file: BackupFile = serde_json::from_slice(raw).map_err(|_| CoreError::BackupCorrupt)?;
    if file.magic != BACKUP_MAGIC {
        return Err(CoreError::BackupCorrupt);
    }
    if file.version != BACKUP_VERSION {
        return Err(CoreError::BackupCorrupt);
    }
    let salt = decode(&file.salt)?;
    if salt.len() != SALT_LEN {
        return Err(CoreError::BackupCorrupt);
    }
    let bytes = match open_payload(&file, &salt, password, false) {
        Err(CoreError::BackupCorrupt) if !is_password_nfc(password) => {
            open_payload(&file, &salt, password, true)?
        }
        other => other?,
    };
    let payload: BackupPayload =
        serde_json::from_slice(&bytes).map_err(|_| CoreError::BackupCorrupt)?;
    Ok((payload.accounts, payload.settings, payload.exported_at))
}

fn open_payload(
    file: &BackupFile,
    salt: &[u8],
    password: &str,
    legacy_unnormalised: bool,
) -> CoreResult<Zeroizing<Vec<u8>>> {
    let key = if legacy_unnormalised {
        derive_key_legacy_unnormalised(password, salt, file.kdf)?
    } else {
        derive_key(password, salt, file.kdf)?
    };
    // Kein Orakel: jeder AEAD-Fehlschlag (falsches Passwort, manipulierter
    // Ciphertext) wird auf denselben BackupCorrupt abgebildet.
    aead_open(key.as_slice(), &file.ct, b"agbak-payload-v1").map_err(|_| CoreError::BackupCorrupt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AlgorithmKind, OtpKind};

    fn sample() -> Vec<Account> {
        vec![Account {
            id: "1".into(),
            label: "alice".into(),
            issuer: "GitHub".into(),
            algorithm: AlgorithmKind::Sha1,
            digits: 6,
            period: 30,
            secret_b32: Zeroizing::new("JBSWY3DPEHPK3PXP".into()),
            kind: OtpKind::Totp,
            counter: 0,
            order: 0,
            created_at: "2026-04-28T10:00:00Z".into(),
        }]
    }

    #[test]
    fn roundtrip() {
        let settings = VaultSettings::default();
        let raw = seal_backup("pwd12345", &sample(), &settings).unwrap();
        let (accs, _s, _t) = open_backup(&raw, "pwd12345").unwrap();
        assert_eq!(accs.len(), 1);
        assert_eq!(accs[0].issuer, "GitHub");
    }

    #[test]
    fn wrong_password_fails() {
        let settings = VaultSettings::default();
        let raw = seal_backup("richtig123", &sample(), &settings).unwrap();
        let err = open_backup(&raw, "falsch4567").unwrap_err();
        // B-123: muss BackupCorrupt sein, NICHT DecryptFailed - die App
        // bildet DecryptFailed auf den Vault-Text ab ("Falsches
        // Master-Passwort..."), der hier faelschlich suggerieren wuerde,
        // Master-Passwort oder Vault seien betroffen.
        assert!(matches!(err, CoreError::BackupCorrupt), "war: {err:?}");
    }

    #[test]
    fn seal_enforces_the_minimum_password_length() {
        let settings = VaultSettings::default();
        let err = seal_backup("short12", &sample(), &settings).unwrap_err();
        assert!(matches!(err, CoreError::InvalidInput(_)), "war: {err:?}");
    }

    #[test]
    fn rejects_wrong_magic() {
        let settings = VaultSettings::default();
        let raw = seal_backup("pwd12345", &sample(), &settings).unwrap();
        let mut file: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        file["magic"] = "XXXX".into();
        let tampered = serde_json::to_vec(&file).unwrap();
        assert!(matches!(
            open_backup(&tampered, "pwd12345").unwrap_err(),
            CoreError::BackupCorrupt
        ));
    }

    #[test]
    fn rejects_newer_version() {
        let settings = VaultSettings::default();
        let raw = seal_backup("pwd12345", &sample(), &settings).unwrap();
        let mut file: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        file["version"] = (BACKUP_VERSION + 1).into();
        let tampered = serde_json::to_vec(&file).unwrap();
        assert!(matches!(
            open_backup(&tampered, "pwd12345").unwrap_err(),
            CoreError::BackupCorrupt
        ));
    }

    /// "Passéwort!" in beiden Unicode-Normalformen - visuell identisch, als
    /// Bytes verschieden (siehe auth-core/src/crypto/kdf.rs).
    const NFC_PW: &str = "Pass\u{00e9}wort!";
    const NFD_PW: &str = "Passe\u{0301}wort!";

    /// Erzeugt ein Backup so, wie es die App VOR dem B-106-Fix angelegt
    /// haette: KEK aus den unnormalisierten Rohbytes. Spiegelt seal_backup,
    /// nur mit der Legacy-Ableitung.
    fn seal_legacy_unnormalised(password: &str, accounts: &[Account], settings: &VaultSettings) -> Vec<u8> {
        let kdf = KdfParams::default();
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let key = derive_key_legacy_unnormalised(password, &salt, kdf).unwrap();
        let payload = BackupPayload {
            accounts: accounts.to_vec(),
            settings: settings.clone(),
            exported_at: "2026-04-28T10:00:00Z".into(),
        };
        let raw = serde_json::to_vec(&payload).unwrap();
        let ct = aead_seal(key.as_slice(), &raw, b"agbak-payload-v1").unwrap();
        let file = BackupFile {
            magic: BACKUP_MAGIC.into(),
            version: BACKUP_VERSION,
            kdf,
            salt: encode(&salt),
            ct,
        };
        serde_json::to_vec_pretty(&file).unwrap()
    }

    #[test]
    fn legacy_unnormalised_backup_still_opens() {
        let settings = VaultSettings::default();
        let raw = seal_legacy_unnormalised(NFD_PW, &sample(), &settings);
        let (accs, _, _) = open_backup(&raw, NFD_PW).expect("Legacy-Backup muss ueber den Fallback oeffnen");
        assert_eq!(accs.len(), 1);
    }

    #[test]
    fn nfc_and_nfd_open_the_same_new_backup() {
        let settings = VaultSettings::default();
        let raw = seal_backup(NFC_PW, &sample(), &settings).unwrap();
        assert!(open_backup(&raw, NFC_PW).is_ok(), "NFC muss oeffnen");
        assert!(open_backup(&raw, NFD_PW).is_ok(), "NFD muss dieselbe Datei oeffnen");
    }

    /// Ein **echtes**, mit dem damaligen Code erzeugtes Backup, eingefroren
    /// als Fixture. Muss sich mit `GOLDEN_PW` weiterhin oeffnen lassen -
    /// ueber jeden kuenftigen Umbau des Sealing-Codes hinweg.
    ///
    /// Analog zum Golden-Vault-Test in `vault.rs`: Roundtrip-Tests im selben
    /// Lauf faenden eine konsistente Aenderung an AAD, Base64-Alphabet oder
    /// JSON-Feldnamen nicht - nur ein Ciphertext, der aelter ist als die
    /// Aenderung, tut das.
    const GOLDEN_BACKUP: &str = r#"{"magic":"AGBK","version":1,"kdf":{"m_cost":65536,"t_cost":3,"p_cost":4},"salt":"u9MoX65-0Tevx9s-LqnDpg","ct":{"nonce":"1VVsdVShnhro035gpcOXMJg7seCLZM50","ct":"A5tSBC0oxVdolJxio9j8M23AR23mvrNTLbF2UAs5Nob9wYTn3snbI_swuL2XXM0Vda6xJfCacrsa5Bk6Mp6OJbdDR2KY4aOTR_a3Mp53jrMTTYUFbZOw6HbVV-qvfQ-L4SumJsAOho3epDgcHKS7cQaJfOiA0eCB65QkVfS8zkdwxdTQ5P1YX04xMVnL75aK0onuDgARfBAnBViFuajF1LU9kpyZVbM5CPay9YVZC-3rBa1oHJnziqJhVlrzm2fYlq8O0A22K7cywkV4V8edqEKcg0MBa8SbiSaTA9eSx1c0yIrvWp0AjhrsKSs8_4ihTi6YULlZAQd1O9GMU5nbW8DtHAvFbHZL045JTjK4ZdKHARWxTBDa61bSSSYKDtAGpYiLOJfU4oSj12k6nzEJjOEUzarWSBSNF5E4z__aDfQwziuXCHhsAefQv-OHyckGS25ei8O0PRqa-4fM1tALKopReRJfBVPEAM-JKl8B31sAi3wP1qGHyg"}}"#;

    const GOLDEN_PW: &str = "goldenes-passwort";

    #[test]
    fn ein_bestehendes_backup_von_der_platte_bleibt_lesbar() {
        let (accs, _settings, exported_at) =
            open_backup(GOLDEN_BACKUP.as_bytes(), GOLDEN_PW).expect("Bestandsbackup MUSS sich weiterhin oeffnen lassen");
        assert_eq!(accs.len(), 1);
        assert_eq!(accs[0].issuer, "GitHub");
        assert_eq!(accs[0].secret_b32.as_str(), "JBSWY3DPEHPK3PXP");
        // exported_at ist der Erzeugungszeitpunkt der Fixture (Utc::now()
        // zum Generierungszeitpunkt) - hier zaehlt nur, dass er unversehrt
        // aus dem Ciphertext kommt, nicht ein bestimmter Wert.
        assert!(exported_at.starts_with("2026-"), "war: {exported_at}");
    }

    #[test]
    fn der_goldene_backup_oeffnet_nicht_mit_falschem_passwort() {
        assert!(matches!(
            open_backup(GOLDEN_BACKUP.as_bytes(), "goldenes-passwort!").unwrap_err(),
            CoreError::BackupCorrupt
        ));
    }
}
