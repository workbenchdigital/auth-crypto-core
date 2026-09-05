//! Parser für otpauth:// URIs.
//!
//! Format (RFC nicht offiziell, aber De-facto-Standard):
//! `otpauth://TYPE/LABEL?secret=BASE32&issuer=...&algorithm=SHA1&digits=6&period=30`
//!
//! `LABEL` ist üblicherweise `Issuer:Account` oder `Account`.

use percent_encoding::percent_decode_str;
use url::Url;
use zeroize::Zeroizing;

use crate::error::{CoreError, CoreResult};
use crate::model::{AccountInput, AlgorithmKind, OtpKind};

pub fn parse_otpauth_uri(uri: &str) -> CoreResult<AccountInput> {
    let trimmed = uri.trim();
    if !trimmed.starts_with("otpauth://") {
        return Err(CoreError::InvalidOtpauth(
            "Schema muss otpauth:// sein".into(),
        ));
    }
    let url = Url::parse(trimmed).map_err(|e| CoreError::InvalidOtpauth(e.to_string()))?;

    let kind = match url.host_str().unwrap_or_default().to_lowercase().as_str() {
        "totp" => OtpKind::Totp,
        "hotp" => {
            return Err(CoreError::InvalidOtpauth(
                "HOTP wird noch nicht unterstützt".into(),
            ))
        }
        other => {
            return Err(CoreError::InvalidOtpauth(format!(
                "Unbekannter Typ: {other}"
            )))
        }
    };

    let label = url.path().trim_start_matches('/');
    let label_decoded = percent_decode_str(label)
        .decode_utf8_lossy()
        .into_owned();
    // L-5: `decode_utf8_lossy` ersetzt ungueltige Byte-Sequenzen stumm durch
    // U+FFFD - ohne Log wuerde ein kaputt kodiertes Label unbemerkt anders
    // ankommen, als es in der Quelle stand.
    if label_decoded.contains('\u{FFFD}') {
        tracing::warn!("otpauth-URI: Label enthielt ungültige UTF-8-Bytes, wurde ersetzt");
    }

    let (issuer_from_label, account_label) = match label_decoded.split_once(':') {
        Some((issuer, account)) => (Some(issuer.trim().to_string()), account.trim().to_string()),
        None => (None, label_decoded.trim().to_string()),
    };

    let mut secret = None;
    let mut issuer_param = None;
    let mut algorithm = AlgorithmKind::default();
    let mut digits: u8 = 6;
    let mut period: u32 = 30;
    let mut counter: u64 = 0;

    for (k, v) in url.query_pairs() {
        match k.to_ascii_lowercase().as_str() {
            "secret" => secret = Some(v.into_owned()),
            "issuer" => issuer_param = Some(v.into_owned()),
            "algorithm" => {
                algorithm = match v.to_ascii_uppercase().as_str() {
                    "SHA1" => AlgorithmKind::Sha1,
                    "SHA256" => AlgorithmKind::Sha256,
                    "SHA512" => AlgorithmKind::Sha512,
                    other => {
                        return Err(CoreError::InvalidOtpauth(format!(
                            "Algorithmus {other} nicht unterstützt"
                        )))
                    }
                }
            }
            "digits" => {
                digits = v
                    .parse::<u8>()
                    .map_err(|_| CoreError::InvalidOtpauth("digits ungültig".into()))?;
            }
            "period" => {
                period = v
                    .parse::<u32>()
                    .map_err(|_| CoreError::InvalidOtpauth("period ungültig".into()))?;
            }
            "counter" => {
                counter = v
                    .parse::<u64>()
                    .map_err(|_| CoreError::InvalidOtpauth("counter ungültig".into()))?;
            }
            _ => {} // unbekannte Parameter ignorieren
        }
    }

    let secret = secret.ok_or_else(|| CoreError::InvalidOtpauth("Parameter 'secret' fehlt".into()))?;

    // Issuer-Auflösung: Query-Parameter hat Vorrang vor Label-Prefix.
    let issuer = issuer_param
        .or(issuer_from_label)
        .unwrap_or_default()
        .trim()
        .to_string();

    let mut acc = AccountInput {
        label: account_label,
        issuer,
        secret_b32: Zeroizing::new(secret),
        algorithm,
        digits,
        period,
        kind,
        counter,
    };
    // B-52: dieselbe Validierung wie add_account (Base32-Dekodierbarkeit,
    // Mindestlaenge, Secret-Normalisierung) - sonst zeigt die Vorschau ein
    // Konto, das beim Commit still verschwindet. Fehler auf InvalidOtpauth
    // abbilden (statt e.to_string() zu übernehmen, was den "Ungültige
    // Eingabe:"-Präfix doppelt verschachteln würde), damit die Meldung
    // otpauth-spezifisch bleibt.
    let cleaned = acc.validate().map_err(|e| match e {
        CoreError::InvalidInput(msg) => CoreError::InvalidOtpauth(msg),
        other => other,
    })?;
    acc.secret_b32 = cleaned;
    Ok(acc)
}

#[cfg(test)]
#[path = "otpauth_tests.rs"]
mod tests;
