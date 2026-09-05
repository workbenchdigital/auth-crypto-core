//! Decoder für `otpauth-migration://offline?data=<base64-proto>`.
//!
//! Format dokumentiert in:
//! - https://alexbakker.me/post/parsing-google-auth-export-qr-code.html
//! - https://github.com/scito/extract_otp_secret_keys
//!
//! Wir nutzen unseren eigenen, minimalen Protobuf-Decoder
//! (`super::proto_min::decode_migration`) – das spart die Build-Zeit-
//! Abhängigkeit auf `protoc` ein und reduziert den binären Footprint.

use base64::Engine;
use percent_encoding::percent_decode_str;
use url::Url;
use zeroize::Zeroizing;

use crate::error::{CoreError, CoreResult};
use crate::model::{AccountInput, AlgorithmKind, OtpKind};

use super::proto_min::decode_migration;

/// Metadaten eines Multi-QR-Migrationsbatches (B-5). `None`, wenn der Export
/// aus nur einem QR-Code besteht (batch_size <= 1, inkl. dem Default 0, wenn
/// ein Exporter die Felder gar nicht sendet).
#[derive(Debug, Clone, Copy)]
pub struct MigrationBatchInfo {
    pub batch_id: u64,
    pub batch_size: u32,
    pub batch_index: u32,
}

pub fn parse_google_migration(
    uri: &str,
) -> CoreResult<(Vec<AccountInput>, Vec<String>, Option<MigrationBatchInfo>)> {
    let trimmed = uri.trim();
    if !trimmed.starts_with("otpauth-migration://") {
        return Err(CoreError::GoogleMigration(
            "Schema muss otpauth-migration:// sein".into(),
        ));
    }
    let url = Url::parse(trimmed).map_err(|e| CoreError::GoogleMigration(e.to_string()))?;

    let mut data_param: Option<String> = None;
    for (k, v) in url.query_pairs() {
        if k == "data" {
            data_param = Some(v.into_owned());
        }
    }
    let data = data_param
        .ok_or_else(|| CoreError::GoogleMigration("Parameter 'data' fehlt".into()))?;

    // B-50: query_pairs() dekodiert Prozent-Escapes UND wandelt ein rohes
    // (nicht prozentkodiertes) '+' in ein Leerzeichen um (form-urlencoded-
    // Semantik) - Standard-Base64 enthaelt haeufig '+', das dabei kaputt
    // ging ("Base64: Invalid symbol 32" = Leerzeichen an der +-Position).
    // Gueltiges Base64 enthaelt nie ein echtes Leerzeichen, daher ist die
    // Rueckwandlung immer sicher.
    let data = data.replace(' ', "+");

    // Manche Apps liefern doppelt-URL-encoded.
    let decoded = percent_decode_str(&data).decode_utf8_lossy().into_owned();
    // L-5: siehe otpauth.rs - stumme U+FFFD-Ersetzung waere hier nicht
    // bemerkbar, bevor der nachfolgende Base64-Decode ohnehin fehlschlaegt.
    if decoded.contains('\u{FFFD}') {
        tracing::warn!("Google-Migration: data-Parameter enthielt ungültige UTF-8-Bytes, wurde ersetzt");
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(decoded.as_bytes())
        .or_else(|_| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(decoded.as_bytes())
        })
        .or_else(|_| {
            base64::engine::general_purpose::URL_SAFE.decode(decoded.as_bytes())
        })
        .map_err(|e| CoreError::GoogleMigration(format!("Base64: {e}")))?;

    let payload = decode_migration(&bytes)?;
    let batch = (payload.batch_size > 1).then_some(MigrationBatchInfo {
        batch_id: payload.batch_id,
        batch_size: payload.batch_size,
        batch_index: payload.batch_index,
    });

    let mut out = Vec::with_capacity(payload.params.len());
    let mut skipped = Vec::new();
    for p in payload.params {
        if p.secret.is_empty() {
            skipped.push("Secret fehlt oder ist leer".to_string());
            continue;
        }
        let alg = match p.algorithm {
            2 => AlgorithmKind::Sha256,
            3 => AlgorithmKind::Sha512,
            // 4 = MD5 → überspringen, totp-rs unterstützt MD5 nicht
            4 => {
                skipped.push("Algorithmus MD5 wird nicht unterstützt".to_string());
                continue;
            }
            _ => AlgorithmKind::Sha1,
        };
        // B-135: vorher fing nur otp_type==1 (HOTP) explizit ab, jeder andere
        // Wert (inkl. 0=Unspecified als proto3-Default bei fehlendem Feld)
        // wurde stillschweigend zu TOTP - ohne den bei Aegis/2FAS bereits
        // etablierten defensiven Wertebereichs-Guard. Jetzt strikt gematcht,
        // wie dort.
        match p.otp_type {
            2 => {}
            1 => {
                skipped.push("HOTP wird noch nicht unterstützt".to_string());
                continue;
            }
            _ => {
                skipped.push("Kontotyp unbekannt".to_string());
                continue;
            }
        }
        let kind = OtpKind::Totp;
        let digits = if p.digits == 2 { 8u8 } else { 6u8 };
        let secret_b32 =
            Zeroizing::new(base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &p.secret));
        let acc = AccountInput {
            label: p.name,
            issuer: p.issuer,
            secret_b32,
            algorithm: alg,
            digits,
            period: 30,
            kind,
            counter: p.counter,
        };
        // B-52: dieselbe Validierung wie add_account (Mindestlaenge, Issuer/
        // Label gesetzt) - sonst zeigt die Vorschau ein Konto, das beim
        // Commit still verschwindet. Der Grund landet zusaetzlich in
        // `skipped` (B-55), statt spurlos zu verschwinden.
        if let Err(e) = acc.validate() {
            skipped.push(e.to_string());
            continue;
        }
        out.push(acc);
    }
    Ok((out, skipped, batch))
}

#[cfg(test)]
#[path = "google_migration_tests.rs"]
mod tests;
