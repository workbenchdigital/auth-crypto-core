//! TOTP-Berechnung (RFC 6238) auf Basis von `totp-rs`.
//!
//! **Zeit-quellen-frei:** Der aktuelle Unix-Zeitstempel wird als Parameter
//! übergeben (`generate_totp(.., now)`), nicht intern via `SystemTime` ermittelt.
//! Das hält den Kern WASM-tauglich (`SystemTime::now` paniert in `wasm32`) und
//! erlaubt harte Tests gegen feste RFC-Vektoren.

use totp_rs::{Algorithm as TotpAlg, Secret, TOTP};
use zeroize::Zeroizing;

use crate::error::{CoreError, CoreResult};
use crate::model::{AlgorithmKind, OtpKind};

/// Eingabeparameter einer TOTP-Berechnung – entkoppelt vom App-`Account`,
/// damit der Kern keine app-spezifischen Felder (id, label, order, …) kennt.
#[derive(Debug, Clone)]
pub struct TotpParams {
    /// B-104: `Zeroizing`, weil hier bei jedem Refresh-Tick fuer JEDES Konto
    /// eine frische Kopie des Secrets entsteht (`get_current_codes` iteriert
    /// den gesamten Bestand). Als nacktes `String` war das die haeufigste
    /// Klartext-Kopie der ganzen App - volumenmaessig deutlich vor dem
    /// langlebigen Vault-Feld selbst.
    pub secret_b32: Zeroizing<String>,
    pub algorithm: AlgorithmKind,
    pub digits: u8,
    pub period: u32,
    pub kind: OtpKind,
}

/// Ergebnis einer TOTP-Berechnung (ohne App-spezifische Konto-ID).
#[derive(Debug, Clone)]
pub struct TotpCode {
    /// Gruppiert formatiert (z. B. "123 456").
    pub code: String,
    /// Roh-Code (nur Ziffern) – für Click-to-Copy.
    pub raw: String,
    pub remaining_seconds: u32,
    pub period: u32,
}

fn map_alg(alg: AlgorithmKind) -> TotpAlg {
    match alg {
        AlgorithmKind::Sha1 => TotpAlg::SHA1,
        AlgorithmKind::Sha256 => TotpAlg::SHA256,
        AlgorithmKind::Sha512 => TotpAlg::SHA512,
    }
}

fn build_totp(params: &TotpParams) -> CoreResult<TOTP> {
    let raw = Secret::Encoded(params.secret_b32.replace(' ', "").to_uppercase())
        .to_bytes()
        .map_err(|e| CoreError::InvalidInput(format!("Base32-Secret ungültig: {e:?}")))?;
    // `new_unchecked`: Wir akzeptieren bewusst auch kürzere Secrets (z. B. die
    // 80-Bit-Standard-Secrets aus Google Authenticator/GitHub), weil reale
    // Provider sich nicht an die 128-Bit-Mindestlänge der RFC halten.
    Ok(TOTP::new_unchecked(
        map_alg(params.algorithm),
        usize::from(params.digits),
        1,
        u64::from(params.period),
        raw,
    ))
}

fn group_code(code: &str) -> String {
    match code.len() {
        6 => format!("{} {}", &code[..3], &code[3..]),
        7 => format!("{} {}", &code[..4], &code[4..]),
        8 => format!("{} {}", &code[..4], &code[4..]),
        _ => code.to_string(),
    }
}

/// Berechnet einen TOTP-Code für den Zeitpunkt `now` (Unix-Sekunden).
///
/// Validiert defensiv gegen ungültige Persistenz-Daten (`period == 0` würde
/// sonst bei `now % 0` panieren; `digits` außerhalb 6..=8 ist unzulässig).
pub fn generate_totp(params: &TotpParams, now: u64) -> CoreResult<TotpCode> {
    if matches!(params.kind, OtpKind::Hotp) {
        return Err(CoreError::InvalidInput(
            "HOTP wird in dieser Version (noch) nicht unterstützt".into(),
        ));
    }
    if params.period == 0 {
        return Err(CoreError::InvalidInput("period muss > 0 sein".into()));
    }
    if !(6..=8).contains(&params.digits) {
        return Err(CoreError::InvalidInput(
            "digits muss zwischen 6 und 8 liegen".into(),
        ));
    }
    let totp = build_totp(params)?;
    let raw = totp.generate(now);
    let code = group_code(&raw);
    let remaining = (params.period as u64 - (now % params.period as u64)) as u32;
    Ok(TotpCode {
        code,
        raw,
        remaining_seconds: remaining,
        period: params.period,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(secret_b32: &str) -> TotpParams {
        TotpParams {
            secret_b32: Zeroizing::new(secret_b32.into()),
            algorithm: AlgorithmKind::Sha1,
            digits: 6,
            period: 30,
            kind: OtpKind::Totp,
        }
    }

    /// Base32-kodiert ein ASCII-Secret, damit die RFC-Vektoren ohne manuell
    /// getippte (fehleranfällige) Base32-Strings auskommen.
    fn b32(ascii: &[u8]) -> String {
        base32::encode(base32::Alphabet::Rfc4648 { padding: false }, ascii)
    }

    #[test]
    fn produces_six_digit_code() {
        let res = generate_totp(&params("JBSWY3DPEHPK3PXP"), 1_700_000_000).unwrap();
        assert_eq!(res.raw.len(), 6);
        assert!(res.raw.chars().all(|c| c.is_ascii_digit()));
        assert_eq!(res.code.len(), 7); // "123 456"
        assert!(res.remaining_seconds >= 1 && res.remaining_seconds <= 30);
    }

    #[test]
    fn invalid_base32_errors() {
        assert!(generate_totp(&params("not-base32!!"), 0).is_err());
    }

    #[test]
    fn rejects_hotp_for_now() {
        let mut p = params("JBSWY3DPEHPK3PXP");
        p.kind = OtpKind::Hotp;
        assert!(generate_totp(&p, 0).is_err());
    }

    #[test]
    fn rejects_zero_period() {
        let mut p = params("JBSWY3DPEHPK3PXP");
        p.period = 0;
        assert!(generate_totp(&p, 0).is_err());
    }

    #[test]
    fn rejects_out_of_range_digits() {
        let mut p = params("JBSWY3DPEHPK3PXP");
        p.digits = 9;
        assert!(generate_totp(&p, 0).is_err());
        p.digits = 0;
        assert!(generate_totp(&p, 0).is_err());
    }

    #[test]
    fn rfc6238_sha1_vector() {
        // RFC 6238 Appendix B: 20-Byte-Secret, T=59s, 8 Ziffern → 94287082.
        let mut p = params(&b32(b"12345678901234567890"));
        p.digits = 8;
        let totp = build_totp(&p).unwrap();
        assert_eq!(totp.generate(59), "94287082");
    }

    #[test]
    fn rfc6238_sha256_vector() {
        let mut p = params(&b32(b"12345678901234567890123456789012"));
        p.algorithm = AlgorithmKind::Sha256;
        p.digits = 8;
        let totp = build_totp(&p).unwrap();
        assert_eq!(totp.generate(59), "46119246");
    }

    #[test]
    fn rfc6238_sha512_vector() {
        let mut p = params(&b32(
            b"1234567890123456789012345678901234567890123456789012345678901234",
        ));
        p.algorithm = AlgorithmKind::Sha512;
        p.digits = 8;
        let totp = build_totp(&p).unwrap();
        assert_eq!(totp.generate(59), "90693936");
    }

    #[test]
    fn algorithm_mapping_changes_output() {
        let secret = b32(b"12345678901234567890123456789012");
        let mk = |alg: AlgorithmKind| {
            let mut p = params(&secret);
            p.algorithm = alg;
            p.digits = 8;
            build_totp(&p).unwrap().generate(59)
        };
        let c1 = mk(AlgorithmKind::Sha1);
        let c256 = mk(AlgorithmKind::Sha256);
        let c512 = mk(AlgorithmKind::Sha512);
        assert_ne!(c1, c256);
        assert_ne!(c1, c512);
        assert_ne!(c256, c512);
    }

    #[test]
    fn remaining_seconds_decreases_within_period() {
        // Bei T=10 (period 30) sind 20 Sekunden übrig.
        let res = generate_totp(&params("JBSWY3DPEHPK3PXP"), 10).unwrap();
        assert_eq!(res.remaining_seconds, 20);
    }
}
