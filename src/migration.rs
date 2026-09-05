//! Versioniertes Vault-Body-Migrations-Framework.
//!
//! Beim Entsperren wird der entschlüsselte Body durch [`migrate_body`] geleitet.
//! Solange `from_version == CURRENT_BODY_VERSION` ist das ein reiner
//! Passthrough (deserialisiert identisch zum direkten `from_slice`). Sobald eine
//! künftige Schema-Änderung eine neue Version einführt, wird in [`step`] eine
//! Migrationsstufe `n -> n+1` ergänzt; bestehende Vaults bleiben dadurch lesbar.
//!
//! Entwurfsprinzip (Integrität): Migrationen laufen über eine
//! JSON-Zwischenrepräsentation (`serde_json::Value`), damit Felder additiv
//! umgeformt werden können, ohne dass alte und neue Rust-Structs gleichzeitig
//! existieren müssen. Eine zu neue Datei (von einer neueren App-Version
//! geschrieben) wird mit klarer Meldung abgelehnt statt fehlinterpretiert.

use serde_json::Value;

use crate::error::{CoreError, CoreResult};

use crate::model::VaultBody;

/// Aktuelle Body-Schema-Version. Wird im Gleichschritt mit der
/// `VaultFile`-Version (`storage::VAULT_VERSION`) erhöht.
pub const CURRENT_BODY_VERSION: u8 = 1;

/// Migriert die entschlüsselten Body-Bytes von `from_version` auf die aktuelle
/// Version und deserialisiert das Ergebnis zu [`VaultBody`].
///
/// - `from_version > CURRENT_BODY_VERSION` → Fehler (App zu alt für die Datei).
/// - `from_version == CURRENT_BODY_VERSION` → Passthrough.
/// - `from_version <  CURRENT_BODY_VERSION` → Migrationskette über [`step`].
pub fn migrate_body(from_version: u8, body_bytes: &[u8]) -> CoreResult<VaultBody> {
    if from_version > CURRENT_BODY_VERSION {
        return Err(CoreError::VaultFormat(format!(
            "Vault-Version {from_version} ist neuer als von dieser App unterstützt \
             ({CURRENT_BODY_VERSION}). Bitte aktualisiere AUth."
        )));
    }

    let mut value: Value = serde_json::from_slice(body_bytes)
        .map_err(|e| CoreError::VaultFormat(format!("Body-JSON: {e}")))?;

    let mut version = from_version;
    while version < CURRENT_BODY_VERSION {
        value = step(version, value)?;
        version += 1;
    }

    serde_json::from_value(value).map_err(|e| {
        CoreError::VaultFormat(format!("Body-Deserialisierung nach Migration: {e}"))
    })
}

/// Eine einzelne Migrationsstufe `from -> from+1`.
///
/// Wird erst aktiv, sobald `CURRENT_BODY_VERSION > 1` ist. Künftige Stufen
/// kommen hier als `match`-Arme dazu, z. B.:
/// ```ignore
/// match from {
///     1 => { /* obj["accounts"][*]["tags"] = [] einsetzen */ Ok(value) }
///     other => Err(...),
/// }
/// ```
fn step(from: u8, _value: Value) -> CoreResult<Value> {
    Err(CoreError::VaultFormat(format!(
        "Keine Migrationsstufe für Vault-Body-Version {from} definiert"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Repräsentatives v1-Body-JSON (Golden Fixture). Bleibt absichtlich als
    /// String eingecheckt: bricht das aktuelle Schema die Lesbarkeit dieses
    /// Formats, schlägt dieser Test fehl – Schutz gegen stille Format-Brüche.
    const GOLDEN_V1_BODY: &str = r#"{
        "accounts": [
            {
                "id": "11111111-1111-1111-1111-111111111111",
                "label": "alice",
                "issuer": "GitHub",
                "algorithm": "SHA1",
                "digits": 6,
                "period": 30,
                "secret_b32": "JBSWY3DPEHPK3PXP",
                "kind": "totp",
                "counter": 0,
                "order": 0,
                "created_at": "2026-01-01T00:00:00Z"
            }
        ],
        "settings": {
            "auto_lock_minutes": 5,
            "cloud_folder_path": null,
            "copy_on_click": true,
            "hello_enabled": false
        }
    }"#;

    #[test]
    fn golden_v1_body_remains_readable() {
        let body = migrate_body(CURRENT_BODY_VERSION, GOLDEN_V1_BODY.as_bytes()).unwrap();
        assert_eq!(body.accounts.len(), 1);
        assert_eq!(body.accounts[0].issuer, "GitHub");
        // B-104: das Feld ist jetzt `Zeroizing<String>` statt `String`. Der
        // Serde-Adapter muss das alte On-Disk-Format unveraendert lesen -
        // sonst waeren mit dem Umstieg saemtliche bestehenden vault.dat- und
        // .agbak-Dateien unlesbar geworden, also alle Konten der Nutzer weg.
        assert_eq!(body.accounts[0].secret_b32.as_str(), "JBSWY3DPEHPK3PXP");
        assert_eq!(body.settings.auto_lock_minutes, 5);
        assert!(body.settings.copy_on_click);
    }

    #[test]
    fn secret_still_serialises_as_a_plain_json_string() {
        // Gegenrichtung zu golden_v1_body_remains_readable: eine neuere
        // Version darf kein Format schreiben, das eine aeltere nicht mehr
        // lesen kann (`Zeroizing` darf nicht als Objekt/Wrapper erscheinen).
        let body = migrate_body(CURRENT_BODY_VERSION, GOLDEN_V1_BODY.as_bytes()).unwrap();
        let json = serde_json::to_string(&body).unwrap();
        assert!(
            json.contains(r#""secret_b32":"JBSWY3DPEHPK3PXP""#),
            "secret_b32 muss ein flacher JSON-String bleiben, war: {json}"
        );
    }

    #[test]
    fn current_version_roundtrips() {
        let original = VaultBody::default();
        let bytes = serde_json::to_vec(&original).unwrap();
        let migrated = migrate_body(CURRENT_BODY_VERSION, &bytes).unwrap();
        assert_eq!(migrated.accounts.len(), original.accounts.len());
        assert_eq!(
            migrated.settings.auto_lock_minutes,
            original.settings.auto_lock_minutes
        );
    }

    #[test]
    fn future_version_is_rejected() {
        let bytes = serde_json::to_vec(&VaultBody::default()).unwrap();
        let err = migrate_body(CURRENT_BODY_VERSION + 1, &bytes).unwrap_err();
        assert!(matches!(err, CoreError::VaultFormat(_)));
    }

    #[test]
    fn corrupt_json_is_rejected() {
        let err = migrate_body(CURRENT_BODY_VERSION, b"not json").unwrap_err();
        assert!(matches!(err, CoreError::VaultFormat(_)));
    }
}
