//! Parser für unverschlüsselte JSON-Exporte von **Aegis** (Android) und
//! **2FAS** (Android/iOS).
//!
//! Formatquellen:
//! - Aegis: <https://github.com/beemdevelopment/Aegis/blob/master/docs/vault.md>
//! - 2FAS: aus dem offenen Backup-Decryptor rekonstruiert
//!   (<https://github.com/elliotwutingfeng/2fas-backup-decryptor>)
//!
//! Reine Text-/Bytes-Verarbeitung, kein Datei-IO — das Einlesen mit
//! Größenbegrenzung (`read_json_file`) bleibt in
//! `src-tauri/src/importers/external_json.rs`.
//!
//! Sicherheitshaltung (wie in `google_migration.rs`): der Dateiinhalt ist
//! **untrusted external input**. Wir parsen deshalb eigene, minimale Structs
//! statt Vendor-Crates, akzeptieren unbekannte Felder stillschweigend
//! (kein `deny_unknown_fields`), begrenzen die Eintragszahl, und ein
//! einzelner kaputter Eintrag kippt nie die ganze Datei — er wird
//! übersprungen.
//!
//! **Passwortgeschützte Exporte werden nicht entschlüsselt.** Das Aegis-
//! Krypto-Format ist zwar dokumentiert, aber eine eigene Implementierung
//! wäre reverse-engineerte Krypto ohne Testvektoren — falsch investiertes
//! Risiko in einem Sicherheitsprodukt. Stattdessen: klare Anweisung an den
//! Nutzer, unverschlüsselt zu exportieren.

use serde::Deserialize;
use serde_json::Value;
use zeroize::Zeroizing;

use crate::error::{CoreError, CoreResult};
use crate::model::{AccountInput, AlgorithmKind, OtpKind, MAX_NAME_CHARS};

/// Obergrenze für Einträge pro Datei. Kein realer Export erreicht das; die
/// Grenze verhindert, dass eine Datei aus Minimal-Objekten (`{},{},…`) beim
/// Deserialisieren ein Vielfaches ihrer Größe an Speicher belegt.
const MAX_ENTRIES: usize = 10_000;

const AEGIS_ENCRYPTED: &str = "Diese Aegis-Datei ist passwortgeschützt. \
Bitte in Aegis ohne Passwort/verschlüsselt exportieren \
(Einstellungen → Backups → Exportieren) und erneut versuchen.";

const TWOFAS_ENCRYPTED: &str = "Diese 2FAS-Datei ist passwortgeschützt. \
Bitte in 2FAS ohne Passwort exportieren und erneut versuchen.";

/// Erkennt das Format anhand der Top-Level-Schlüssel und delegiert.
/// Aegis: `db`. 2FAS: `services` (bzw. `servicesEncrypted` bei Passwortschutz).
pub fn parse_json_backup(raw: &str) -> CoreResult<(Vec<AccountInput>, Vec<String>)> {
    // BOM abschneiden: in Notepad o. Ä. erneut gespeicherte Exporte tragen ihn,
    // und serde_json würde daran mit einer verwirrenden Meldung scheitern.
    let raw = raw.trim_start_matches('\u{feff}').trim();
    // Der Text dieses Fehlers ist unbedenklich: serde_json meldet bei
    // Syntaxfehlern nur Zeile/Spalte, nie Dateiinhalt.
    let value: Value = serde_json::from_str(raw).map_err(|e| {
        CoreError::invalid_input(format!("Die Datei ist kein gültiges JSON ({e})."))
    })?;

    if value.get("db").is_some() {
        parse_aegis(value)
    } else if value.get("services").is_some() {
        parse_twofas(value)
    } else if value.get("servicesEncrypted").is_some() {
        Err(CoreError::TwoFasImport(TWOFAS_ENCRYPTED.into()))
    } else {
        Err(CoreError::invalid_input(
            "Die Datei wurde weder als Aegis- noch als 2FAS-Export erkannt. \
Erwartet wird ein unverschlüsselter JSON-Export aus einer dieser Apps.",
        ))
    }
}

// ────────────────────────────────────────────────────────────
// Aegis
// ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct AegisRoot {
    #[serde(default)]
    header: Option<AegisHeader>,
    #[serde(default)]
    db: Value,
}

#[derive(Deserialize)]
struct AegisHeader {
    #[serde(default)]
    slots: Option<Value>,
}

/// B-54: hoechste `db.version`, deren Feld-Mapping hier verifiziert ist.
/// Aegis' Referenzimplementierung lehnt neuere Versionen ab, statt sie
/// bestmoeglich zu interpretieren - ein unbekanntes zukuenftiges Format
/// koennte Felder anders belegen und wuerde sonst still falsch gemappt.
const AEGIS_MAX_KNOWN_DB_VERSION: i64 = 3;

#[derive(Deserialize)]
struct AegisDb {
    #[serde(default)]
    version: Option<i64>,
    #[serde(default)]
    entries: Vec<AegisEntry>,
}

#[derive(Deserialize)]
struct AegisEntry {
    #[serde(rename = "type", default)]
    kind: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    issuer: Option<String>,
    #[serde(default)]
    info: Option<AegisInfo>,
}

#[derive(Deserialize, Default)]
struct AegisInfo {
    #[serde(default)]
    secret: Option<String>,
    #[serde(default)]
    algo: Option<String>,
    #[serde(default)]
    digits: Option<i64>,
    #[serde(default)]
    period: Option<i64>,
    #[serde(default)]
    counter: Option<i64>,
}

fn parse_aegis(value: Value) -> CoreResult<(Vec<AccountInput>, Vec<String>)> {
    // Achtung: `serde_json::from_value`-Fehler enthalten bei Typkonflikten den
    // *Wert* aus der Datei ("invalid type: string \"…\", expected i64").
    // Diese Meldungen gehen 1:1 ins Frontend (siehe error.rs) – deshalb hier
    // nie den serde-Text durchreichen, sonst kann ein Secret im Toast landen.
    let root: AegisRoot = serde_json::from_value(value).map_err(|_| {
        CoreError::AegisImport("Die Datei hat nicht den erwarteten Aufbau eines Aegis-Exports.".into())
    })?;

    // Verschlüsselt erkennt man an zwei unabhängigen Merkmalen: `db` ist dann
    // ein Base64-String statt eines Objekts, und `header.slots` ist gefüllt.
    // Beide prüfen — ein manipuliertes Backup soll nicht an einem davon
    // vorbeikommen und in den Entry-Parser laufen.
    let slots_filled = root
        .header
        .as_ref()
        .and_then(|h| h.slots.as_ref())
        .is_some_and(|s| !s.is_null());
    if root.db.is_string() || slots_filled {
        return Err(CoreError::AegisImport(AEGIS_ENCRYPTED.into()));
    }

    let db: AegisDb = serde_json::from_value(root.db).map_err(|_| {
        CoreError::AegisImport("Der Abschnitt 'db' der Datei ist unlesbar.".into())
    })?;
    if db.version.is_some_and(|v| v > AEGIS_MAX_KNOWN_DB_VERSION) {
        return Err(CoreError::AegisImport(format!(
            "Unbekanntes Aegis-Export-Format (db.version {}, unterstützt bis {}). Bitte AUth aktualisieren.",
            db.version.unwrap(),
            AEGIS_MAX_KNOWN_DB_VERSION
        )));
    }
    check_count("Aegis", db.entries.len())?;

    let raws = db
        .entries
        .into_iter()
        .map(|e| {
            let info = e.info.unwrap_or_default();
            RawEntry {
                kind: e.kind.unwrap_or_default(),
                issuer: e.issuer.unwrap_or_default(),
                label: e.name.unwrap_or_default(),
                secret: info.secret.unwrap_or_default(),
                algo: info.algo.unwrap_or_default(),
                digits: info.digits,
                period: info.period,
                counter: info.counter,
            }
        })
        .collect();

    let (out, skipped) = convert("Aegis", raws);
    if out.is_empty() {
        return Err(CoreError::AegisImport(
            "Die Datei enthält keine importierbaren TOTP-/HOTP-Einträge.".into(),
        ));
    }
    Ok((out, skipped))
}

// ────────────────────────────────────────────────────────────
// 2FAS
// ────────────────────────────────────────────────────────────

/// B-54: hoechste `schemaVersion`, deren Feld-Mapping hier verifiziert ist -
/// gleiche Begruendung wie `AEGIS_MAX_KNOWN_DB_VERSION`.
const TWOFAS_MAX_KNOWN_SCHEMA_VERSION: i64 = 4;

#[derive(Deserialize)]
struct TwoFasRoot {
    #[serde(rename = "schemaVersion", default)]
    schema_version: Option<i64>,
    #[serde(default)]
    services: Option<Vec<TwoFasService>>,
    #[serde(rename = "servicesEncrypted", default)]
    services_encrypted: Option<Value>,
}

#[derive(Deserialize)]
struct TwoFasService {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    secret: Option<String>,
    #[serde(default)]
    otp: Option<TwoFasOtp>,
}

#[derive(Deserialize, Default)]
struct TwoFasOtp {
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    account: Option<String>,
    #[serde(default)]
    issuer: Option<String>,
    #[serde(default)]
    algorithm: Option<String>,
    #[serde(default)]
    digits: Option<i64>,
    #[serde(default)]
    period: Option<i64>,
    #[serde(default)]
    counter: Option<i64>,
    #[serde(rename = "tokenType", default)]
    token_type: Option<String>,
}

fn parse_twofas(value: Value) -> CoreResult<(Vec<AccountInput>, Vec<String>)> {
    // Kein serde-Fehlertext ins Frontend – Begründung siehe `parse_aegis`.
    let root: TwoFasRoot = serde_json::from_value(value).map_err(|_| {
        CoreError::TwoFasImport("Die Datei hat nicht den erwarteten Aufbau eines 2FAS-Exports.".into())
    })?;
    if root.schema_version.is_some_and(|v| v > TWOFAS_MAX_KNOWN_SCHEMA_VERSION) {
        return Err(CoreError::TwoFasImport(format!(
            "Unbekanntes 2FAS-Export-Format (schemaVersion {}, unterstützt bis {}). Bitte AUth aktualisieren.",
            root.schema_version.unwrap(),
            TWOFAS_MAX_KNOWN_SCHEMA_VERSION
        )));
    }

    let services = root.services.unwrap_or_default();
    check_count("2FAS", services.len())?;
    // Passwortgeschützte Exporte tragen die Konten in `servicesEncrypted`;
    // `services` ist dann leer oder fehlt. Diese Kombination liefert die
    // hilfreiche Meldung statt eines nichtssagenden "keine Einträge".
    if services.is_empty() && root.services_encrypted.is_some() {
        return Err(CoreError::TwoFasImport(TWOFAS_ENCRYPTED.into()));
    }

    let raws = services
        .into_iter()
        .map(|s| {
            let name = s.name.unwrap_or_default();
            let otp = s.otp.unwrap_or_default();
            RawEntry {
                // Fehlender tokenType: ältere Exporte kennen das Feld nicht,
                // TOTP ist dort der einzige Typ.
                kind: otp.token_type.unwrap_or_else(|| "totp".into()),
                issuer: otp.issuer.filter(|v| !v.trim().is_empty()).unwrap_or_else(|| name.clone()),
                label: otp
                    .account
                    .or(otp.label)
                    .filter(|v| !v.trim().is_empty())
                    .unwrap_or(name),
                secret: s.secret.unwrap_or_default(),
                algo: otp.algorithm.unwrap_or_default(),
                digits: otp.digits,
                period: otp.period,
                counter: otp.counter,
            }
        })
        .collect();

    let (out, skipped) = convert("2FAS", raws);
    if out.is_empty() {
        return Err(CoreError::TwoFasImport(
            "Die Datei enthält keine importierbaren TOTP-/HOTP-Einträge.".into(),
        ));
    }
    Ok((out, skipped))
}

// ────────────────────────────────────────────────────────────
// Gemeinsame Validierung
// ────────────────────────────────────────────────────────────

/// Formatneutrale Zwischenform. Beide Parser normalisieren hierauf, damit die
/// eigentliche Validierung nur einmal existiert.
struct RawEntry {
    kind: String,
    issuer: String,
    label: String,
    secret: String,
    algo: String,
    digits: Option<i64>,
    period: Option<i64>,
    counter: Option<i64>,
}

/// Validiert die Rohwerte und verwirft einzelne unbrauchbare Einträge, statt
/// die ganze Datei abzulehnen. Die Prüfungen spiegeln bewusst die von
/// `commands::accounts::add_account` — sonst zeigt die Vorschau Konten an, die
/// beim Commit still verschwinden. Zweiter Rückgabewert: die Skip-Gründe
/// (B-55) - vorher nur geloggt, im Release für niemanden sichtbar.
fn convert(source: &str, raws: Vec<RawEntry>) -> (Vec<AccountInput>, Vec<String>) {
    let mut out = Vec::with_capacity(raws.len());
    let mut skipped = Vec::new();
    for (i, r) in raws.into_iter().enumerate() {
        let kind = match r.kind.to_ascii_lowercase().as_str() {
            "totp" => OtpKind::Totp,
            // hotp/steam/motp/yandex haben eigene Code-Ableitungen bzw. sind
            // (noch) nicht implementiert. Raten waere schlimmer als Ueberspringen.
            other => {
                skip(
                    source,
                    i,
                    &format!("Typ '{}' nicht unterstützt", clip(other, 24)),
                    &mut skipped,
                );
                continue;
            }
        };

        let algorithm = match r.algo.to_ascii_uppercase().as_str() {
            "SHA1" | "" => AlgorithmKind::Sha1,
            "SHA256" => AlgorithmKind::Sha256,
            "SHA512" => AlgorithmKind::Sha512,
            other => {
                skip(
                    source,
                    i,
                    &format!("Algorithmus '{}' nicht unterstützt", clip(other, 24)),
                    &mut skipped,
                );
                continue;
            }
        };

        // Sicherer i64→u8/u32-Cast (verhindert Wraparound bei einer
        // präparierten Datei); die eigentliche Wertebereichsprüfung
        // (6..=8 bzw. >0) übernimmt AccountInput::validate weiter unten.
        let digits: u8 = match r.digits.unwrap_or(6).try_into() {
            Ok(d) => d,
            Err(_) => {
                skip(
                    source,
                    i,
                    "Stellenzahl außerhalb des gültigen Bereichs",
                    &mut skipped,
                );
                continue;
            }
        };
        let period: u32 = match r.period.unwrap_or(30).try_into() {
            Ok(p) => p,
            Err(_) => {
                skip(
                    source,
                    i,
                    "Intervall außerhalb des gültigen Bereichs",
                    &mut skipped,
                );
                continue;
            }
        };

        // Negative Counter kommen in keinem gültigen Export vor; 0 ist der
        // sichere Startwert (HOTP-Resync macht der Dienst ohnehin).
        let counter = r.counter.unwrap_or(0).max(0) as u64;

        let mut acc = AccountInput {
            label: clip(r.label.trim(), MAX_NAME_CHARS),
            issuer: clip(r.issuer.trim(), MAX_NAME_CHARS),
            secret_b32: Zeroizing::new(r.secret),
            algorithm,
            digits,
            period,
            kind,
            counter,
        };
        // B-52: einzige Validierungsquelle, dieselbe wie add_account -
        // Vorschau und Commit können dadurch strukturell nicht mehr divergieren.
        match acc.validate() {
            Ok(cleaned_secret) => acc.secret_b32 = cleaned_secret,
            Err(e) => {
                skip(source, i, &e.to_string(), &mut skipped);
                continue;
            }
        }

        out.push(acc);
    }
    (out, skipped)
}

/// Übersprungene Einträge werden ohne Namen und ohne Secret protokolliert —
/// nur Position und Grund. Logs sind kein Ort für Kontodaten. Der Grund
/// landet zusätzlich in `out` (B-55), damit er die UI erreicht statt nur im
/// (im Release unsichtbaren) Log zu verschwinden.
fn skip(source: &str, index: usize, reason: &str, out: &mut Vec<String>) {
    tracing::warn!("{source}-Import: Eintrag {index} übersprungen ({reason})");
    out.push(reason.to_string());
}

/// Kürzt fremdkontrollierte Strings auf eine feste Zeichenzahl – für Logs und
/// für alles, was dauerhaft im Vault landet. Schneidet an Zeichen-, nicht an
/// Byte-Grenzen, kann also kein ungültiges UTF-8 erzeugen.
fn clip(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// Begrenzt die Anzahl der Einträge, bevor daraus Konten gebaut werden.
fn check_count(source: &str, n: usize) -> CoreResult<()> {
    if n > MAX_ENTRIES {
        return Err(CoreError::invalid_input(format!(
            "Die {source}-Datei enthält mehr als {MAX_ENTRIES} Einträge und wird nicht verarbeitet."
        )));
    }
    Ok(())
}

#[cfg(test)]
#[path = "external_json_tests.rs"]
mod tests;
