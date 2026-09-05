//! Argon2id-basierte Schlüsselableitung (KDF).
//!
//! Default-Parameter folgen OWASP-Empfehlung 2026: m = 64 MiB, t = 3, p = 4.
//! Daraus entsteht ein 32-Byte-Key-Encryption-Key (KEK), mit dem der eigentliche
//! `MasterKey` (DEK) per AEAD verschlüsselt wird.

use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{CoreError, CoreResult};

pub const SALT_LEN: usize = 16;
pub const KEY_LEN: usize = 32;

/// Persistierte KDF-Parameter (Teil des Vault-Headers).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory-Cost in KiB.
    pub m_cost: u32,
    /// Iterationen.
    pub t_cost: u32,
    /// Parallelität.
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost: 64 * 1024, // 64 MiB
            t_cost: 3,
            p_cost: 4,
        }
    }
}

impl KdfParams {
    fn build_argon2(&self) -> CoreResult<Argon2<'static>> {
        let params = Params::new(self.m_cost, self.t_cost, self.p_cost, Some(KEY_LEN))
            .map_err(|e| CoreError::Crypto(format!("Argon2-Parameter ungültig: {e}")))?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }
}

/// Ist das Passwort bereits in Unicode-NFC? Reine ASCII-Strings sind es
/// immer.
///
/// B-106: Die Aufrufer nutzen das, um den Legacy-Fallback (siehe
/// `derive_key_legacy_unnormalised`) zu ueberspringen, wenn er ohnehin
/// bitgleich mit dem normalen Pfad waere - sonst kostete jeder
/// fehlgeschlagene Entsperrversuch eine zweite, sinnlose Argon2-Ableitung
/// (64 MiB, t=3).
pub fn is_password_nfc(password: &str) -> bool {
    unicode_normalization::is_nfc(password)
}

/// Leitet aus Passwort + Salt einen 32-Byte-Schlüssel ab.
///
/// B-106: Das Passwort wird vorher auf Unicode-NFC normalisiert. Ohne das
/// erzeugen zwei visuell identische Eingaben verschiedene Byte-Folgen und
/// damit verschiedene Keys - `"Passéwort!"` als NFC ist
/// `Pass\u{e9}wort!`, als NFD `Passe\u{301}wort!`. Welche Form entsteht,
/// haengt an Tastaturlayout, IME und Passwort-Manager. Bei einer App ohne
/// jede Passwort-Wiederherstellung ist ein dadurch ausgesperrter Nutzer ein
/// endgueltiger Datenverlust.
///
/// Rückgabe ist `Zeroizing` und wird beim Drop aus dem RAM gelöscht.
pub fn derive_key(
    password: &str,
    salt: &[u8],
    params: KdfParams,
) -> CoreResult<Zeroizing<[u8; KEY_LEN]>> {
    use unicode_normalization::UnicodeNormalization;
    // Eigene Zeroizing-Kopie: die Normalform ist genauso schutzbeduerftig
    // wie das Original.
    let normalised = Zeroizing::new(password.nfc().collect::<String>());
    derive_key_from_bytes(normalised.as_bytes(), salt, params)
}

/// Leitet den Schlüssel aus den ROHEN Passwort-Bytes ab, ohne Normalisierung.
///
/// **Nur für Kompatibilität mit Vaults und `.agbak`-Backups, die vor dem
/// B-106-Fix angelegt wurden.** Deren KEK stammt aus den unnormalisierten
/// Bytes; wuerde man sie nur noch ueber `derive_key` oeffnen, waeren alle
/// Bestaende mit Nicht-ASCII-Passwort unwiederbringlich verloren - genau der
/// Schaden, den B-106 verhindern soll.
///
/// Aufrufer verwenden das ausschliesslich als zweiten Versuch, nachdem
/// `derive_key` mit einem Entschluesselungsfehler gescheitert ist, und nur
/// wenn `is_password_nfc` false liefert (sonst waeren beide Pfade identisch).
/// Für alles Neue ist `derive_key` die richtige Funktion.
pub fn derive_key_legacy_unnormalised(
    password: &str,
    salt: &[u8],
    params: KdfParams,
) -> CoreResult<Zeroizing<[u8; KEY_LEN]>> {
    derive_key_from_bytes(password.as_bytes(), salt, params)
}

fn derive_key_from_bytes(
    password: &[u8],
    salt: &[u8],
    params: KdfParams,
) -> CoreResult<Zeroizing<[u8; KEY_LEN]>> {
    if salt.len() != SALT_LEN {
        return Err(CoreError::Crypto(format!(
            "Salt-Länge {} ≠ erwartete {}",
            salt.len(),
            SALT_LEN
        )));
    }
    let argon2 = params.build_argon2()?;
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(password, salt, out.as_mut_slice())
        .map_err(|e| CoreError::Crypto(format!("Argon2 fehlgeschlagen: {e}")))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_params() -> KdfParams {
        // schnellere Params nur für Tests
        KdfParams {
            m_cost: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
        }
    }

    #[test]
    fn derives_key_deterministically() {
        let salt = [42u8; SALT_LEN];
        let a = derive_key("hunter2", &salt, fast_params()).unwrap();
        let b = derive_key("hunter2", &salt, fast_params()).unwrap();
        assert_eq!(a.as_slice(), b.as_slice());
        assert_eq!(a.len(), KEY_LEN);
    }

    #[test]
    fn different_passwords_diverge() {
        let salt = [1u8; SALT_LEN];
        let a = derive_key("foo", &salt, fast_params()).unwrap();
        let b = derive_key("bar", &salt, fast_params()).unwrap();
        assert_ne!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn wrong_salt_length_errors() {
        let err = derive_key("x", &[0u8; 8], fast_params()).unwrap_err();
        assert!(matches!(err, CoreError::Crypto(_)));
    }

    /// "Passéwort!" in beiden Unicode-Normalformen: einmal mit dem
    /// vorkomponierten é (U+00E9), einmal mit e + kombinierendem Akut
    /// (U+0065 U+0301). Visuell identisch, als Bytes verschieden.
    const NFC_PW: &str = "Pass\u{00e9}wort!";
    const NFD_PW: &str = "Passe\u{0301}wort!";

    #[test]
    fn nfc_and_nfd_of_the_same_password_derive_the_same_key() {
        // B-106: der Kern des Fixes. Ohne Normalisierung haengt der Key an
        // der Eingabequelle (Tastatur/IME/Passwort-Manager) statt am
        // Passwort - und bei einer App ohne Wiederherstellung sperrt das
        // Nutzer endgueltig aus.
        assert_ne!(NFC_PW.as_bytes(), NFD_PW.as_bytes(), "Fixture muss sich in den Bytes unterscheiden");
        let salt = [9u8; SALT_LEN];
        let a = derive_key(NFC_PW, &salt, fast_params()).unwrap();
        let b = derive_key(NFD_PW, &salt, fast_params()).unwrap();
        assert_eq!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn legacy_derivation_stays_byte_exact_and_differs_from_the_normalised_one() {
        // Der Legacy-Pfad DARF nicht normalisieren - sonst koennte er einen
        // vor B-106 angelegten NFD-Vault nicht mehr oeffnen, und der
        // Fallback waere wirkungslos.
        let salt = [9u8; SALT_LEN];
        let legacy_nfd = derive_key_legacy_unnormalised(NFD_PW, &salt, fast_params()).unwrap();
        let legacy_nfc = derive_key_legacy_unnormalised(NFC_PW, &salt, fast_params()).unwrap();
        assert_ne!(
            legacy_nfd.as_slice(),
            legacy_nfc.as_slice(),
            "Legacy muss die Rohbytes unterscheiden"
        );

        let normalised = derive_key(NFD_PW, &salt, fast_params()).unwrap();
        assert_ne!(
            legacy_nfd.as_slice(),
            normalised.as_slice(),
            "Legacy-NFD und normalisiert muessen verschieden sein - sonst braeuchte es den Fallback nicht"
        );
        // Fuer bereits-NFC-Eingaben sind beide Pfade identisch, deshalb
        // ueberspringt der Aufrufer den Fallback dort (is_password_nfc).
        assert_eq!(
            legacy_nfc.as_slice(),
            derive_key(NFC_PW, &salt, fast_params()).unwrap().as_slice()
        );
    }

    #[test]
    fn is_password_nfc_detects_the_two_forms() {
        assert!(is_password_nfc(NFC_PW));
        assert!(!is_password_nfc(NFD_PW));
        // ASCII ist immer NFC - der Normalfall laeuft nie in den Fallback.
        assert!(is_password_nfc("hunter2"));
        assert!(is_password_nfc(""));
    }
}
