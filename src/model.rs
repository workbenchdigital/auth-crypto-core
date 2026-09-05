//! Plattformneutrale Datenmodell-Typen des Vaults.
//!
//! O-3 Schritt 3: Account, VaultBody und VaultSettings sind reine Daten
//! plus Validierung - kein Dateisystem, kein OS. Sie liegen deshalb hier
//! und nicht in der App, damit Tauri-Variante und kuenftige
//! Chrome-Extension dasselbe Vault-Format teilen statt zwei divergierende
//! Implementierungen zu pflegen.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{CoreError, CoreResult};

/// TOTP/HOTP-Hash-Algorithmus.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum AlgorithmKind {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

/// OTP-Typ. HOTP ist modelliert, aber noch nicht implementiert.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum OtpKind {
    #[default]
    Totp,
    Hotp,
}

/// Vollständige Account-Repräsentation – wird ausschließlich im verschlüsselten
/// Vault-Body gespeichert. Niemals direkt ans Frontend reichen.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub id: String,
    pub label: String,
    pub issuer: String,
    pub algorithm: AlgorithmKind,
    pub digits: u8,
    pub period: u32,
    /// TOTP-Seed in Base32 (kompatibel zu otpauth://).
    ///
    /// B-104: `Zeroizing`, analog zu `AccountInput::secret_b32`. Diese
    /// Struktur liegt in `VaultBody.accounts` waehrend der GESAMTEN
    /// entsperrten Session im RAM - also ungleich laenger als der
    /// Import-Staging-Puffer, fuer den B-2 dasselbe bereits durchgesetzt hat.
    /// `VaultState::lock()` setzt `body = None`, was den `Vec<Account>`
    /// droppt; ohne Zeroizing gibt Rust den Speicher nur frei, ohne ihn zu
    /// ueberschreiben - die Klartext-Secrets aller Konten blieben im Heap
    /// stehen, obwohl die App sich als gesperrt auswies.
    #[serde(with = "zeroizing_string")]
    pub secret_b32: Zeroizing<String>,
    pub kind: OtpKind,
    #[serde(default)]
    pub counter: u64,
    #[serde(default)]
    pub order: u32,
    #[serde(default = "now_iso")]
    pub created_at: String,
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Was das Frontend sieht: KEINE Secrets, nur Metadaten plus
/// einen aus dem Issuer abgeleiteten Farbcode für die UI.
#[derive(Debug, Clone, Serialize)]
pub struct PublicAccount {
    pub id: String,
    pub label: String,
    pub issuer: String,
    pub algorithm: AlgorithmKind,
    pub digits: u8,
    pub period: u32,
    pub kind: OtpKind,
    pub order: u32,
    /// Hex-Farbe (RGB), aus Issuer/Label gehasht – für UI-Akzent.
    pub color_hint: String,
    /// Zwei-Zeichen-Initialen (z. B. "GH" für GitHub).
    pub initials: String,
}

impl From<&Account> for PublicAccount {
    fn from(a: &Account) -> Self {
        Self {
            id: a.id.clone(),
            label: a.label.clone(),
            issuer: a.issuer.clone(),
            algorithm: a.algorithm,
            digits: a.digits,
            period: a.period,
            kind: a.kind,
            order: a.order,
            color_hint: derive_color(&a.issuer, &a.label),
            initials: derive_initials(&a.issuer, &a.label),
        }
    }
}

fn derive_color(issuer: &str, label: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(issuer.to_lowercase().as_bytes());
    h.update(b":");
    h.update(label.to_lowercase().as_bytes());
    let d = h.finalize();
    // u32-Arithmetik, sonst Overflow bei d[0]=255 * 360 > u16::MAX.
    let hue = (u32::from(d[0]) * 360 / 255) % 360;
    hsl_to_hex(hue as f32, 0.55, 0.55)
}

fn hsl_to_hex(h: f32, s: f32, l: f32) -> String {
    // Standard-HSL → RGB.
    let c = (1.0 - (2.0 * l - 1.0).abs()) * s;
    let h_prime = h / 60.0;
    let x = c * (1.0 - (h_prime % 2.0 - 1.0).abs());
    let (r1, g1, b1) = match h_prime as i32 {
        0 => (c, x, 0.0),
        1 => (x, c, 0.0),
        2 => (0.0, c, x),
        3 => (0.0, x, c),
        4 => (x, 0.0, c),
        _ => (c, 0.0, x),
    };
    let m = l - c / 2.0;
    let r = ((r1 + m) * 255.0).round() as u8;
    let g = ((g1 + m) * 255.0).round() as u8;
    let b = ((b1 + m) * 255.0).round() as u8;
    format!("#{:02x}{:02x}{:02x}", r, g, b)
}

fn derive_initials(issuer: &str, label: &str) -> String {
    let source = if !issuer.trim().is_empty() {
        issuer
    } else {
        label
    };
    let cleaned = source.trim();
    if cleaned.is_empty() {
        return "??".into();
    }

    // E-Mail-Adressen: erste zwei Buchstaben des Local-Parts → "alice@…" → "AL".
    if let Some((local, _)) = cleaned.split_once('@') {
        return first_two_chars_upper(local);
    }

    // Wörter trennen an Nicht-Alphanumerischen.
    let words: Vec<&str> = cleaned
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect();
    match words.as_slice() {
        [] => "??".into(),
        // Genau ein Wort: zwei Buchstaben aus diesem Wort ("Google" → "GO").
        [w] => first_two_chars_upper(w),
        // Mehrere Wörter: jeweils Anfangsbuchstabe ("Acme Inc" → "AI").
        [w1, w2, ..] => {
            let a = first_char_upper(w1);
            let b = first_char_upper(w2);
            format!("{a}{b}")
        }
    }
}

fn first_two_chars_upper(s: &str) -> String {
    let mut chars = s.chars();
    let a = chars
        .next()
        .map(|c| c.to_uppercase().to_string())
        .unwrap_or_default();
    let b = chars
        .next()
        .map(|c| c.to_uppercase().to_string())
        .unwrap_or_else(|| a.clone());
    format!("{a}{b}")
}

fn first_char_upper(s: &str) -> String {
    s.chars()
        .next()
        .map(|c| c.to_uppercase().to_string())
        .unwrap_or_default()
}

/// Eingabe vom Frontend für ein neu hinzuzufügendes Konto, bzw. Zwischenform
/// eines geparsten Imports vor dem Commit in den Vault.
/// `Serialize` zusätzlich, weil die Importer (parse_uri / scan_qr_*) sie
/// als Vorschau ans Frontend zurückgeben können.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInput {
    pub label: String,
    pub issuer: String,
    /// TOTP-Seed in Base32. `Zeroizing`, weil `AccountInput` u.a. im
    /// Import-Staging-Puffer (`ImportStagingState`) laenger im RAM liegt als
    /// ein normaler Funktionsparameter (B-2) - beim Drop (Vec::clear, Scope-
    /// Ende) wird der Speicher aktiv überschrieben statt nur freigegeben.
    #[serde(with = "zeroizing_string")]
    pub secret_b32: Zeroizing<String>,
    #[serde(default)]
    pub algorithm: AlgorithmKind,
    #[serde(default = "default_digits")]
    pub digits: u8,
    #[serde(default = "default_period")]
    pub period: u32,
    #[serde(default)]
    pub kind: OtpKind,
    #[serde(default)]
    pub counter: u64,
}

fn default_digits() -> u8 {
    6
}

fn default_period() -> u32 {
    30
}

/// `zeroize` bringt kein Serde-Feature mit - dieses Modul behandelt
/// `Zeroizing<String>` fuer (De-)Serialisierung wie ein normales `String`.
mod zeroizing_string {
    use serde::{Deserialize, Deserializer, Serializer};
    use zeroize::Zeroizing;

    pub fn serialize<S: Serializer>(v: &Zeroizing<String>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(v.as_str())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
        Ok(Zeroizing::new(String::deserialize(d)?))
    }
}

/// Obergrenze für Issuer/Label. `external_json.rs` clipt JSON-Importe schon
/// vorher auf diesen Wert (Defense-in-Depth); hier ist es die tatsächliche
/// Durchsetzung für alle Pfade (manuell, otpauth-URI, Google-Migration,
/// Restore) - B-53: ein präparierter QR-Code konnte sonst beliebig lange
/// Strings dauerhaft in den Vault schreiben.
pub const MAX_NAME_CHARS: usize = 256;

/// Der gemeinsame Validierungskern hinter `AccountInput::validate()` und
/// `Account::validate()`.
///
/// Arbeitet auf den Feldern statt auf einem Struct, weil die beiden Typen
/// dasselbe pruefen muessen, aber nicht dieselbe Form haben: `AccountInput`
/// haelt das Secret als `Zeroizing<String>` und kennt id/order/created_at
/// nicht, `Account` ist der fertige Vault-Eintrag. B-153: der Restore-Pfad
/// bekam diese Pruefung dadurch frueher gar nicht - die Regeln lagen nur als
/// Methode auf dem falschen Typ. Gibt bei Erfolg das normalisierte Secret
/// zurueck.
fn validate_account_fields(
    label: &str,
    issuer: &str,
    secret_b32: &str,
    digits: u8,
    period: u32,
    kind: OtpKind,
) -> CoreResult<Zeroizing<String>> {
    if label.trim().is_empty() && issuer.trim().is_empty() {
        return Err(CoreError::invalid_input("Issuer oder Label muss gesetzt sein"));
    }
    // B-53: an dieser einzigen Stelle geprüft, statt in jedem Importer
    // separat - deckt otpauth-URI und Google-Migration ab, die vorher
    // gar keine Längenbegrenzung hatten.
    if label.chars().count() > MAX_NAME_CHARS || issuer.chars().count() > MAX_NAME_CHARS {
        return Err(CoreError::invalid_input(format!(
            "Issuer/Label dürfen maximal {MAX_NAME_CHARS} Zeichen lang sein"
        )));
    }
    // '=' zusätzlich zu Leerzeichen/Bindestrich strippen: Base32-Padding
    // aus Provider-QR-Codes ist nicht exotisch (B-52-Reproduktion).
    // B-104: beide Normalisierungsstufen einzeln wrappen - `replace` und
    // `to_uppercase` legen je einen eigenen Klartext-String an, und die
    // Zwischenstufe wuerde sonst unueberschrieben gedroppt.
    let stripped = Zeroizing::new(secret_b32.replace([' ', '-', '='], ""));
    let cleaned_secret = Zeroizing::new(stripped.to_uppercase());
    if cleaned_secret.is_empty() {
        return Err(CoreError::invalid_input("Secret darf nicht leer sein"));
    }
    // Base32 dekodierbar und Länge ≥ 80 Bit (10 Byte) wäre RFC-konform,
    // viele Provider liefern aber 16-Zeichen-Secrets (= 10 Byte). Wir akzeptieren ab 8 Bytes.
    // B-104: `bytes` ist der rohe, dekodierte HMAC-Seed - das eigentliche
    // Schluesselmaterial, noch sensibler als seine Base32-Darstellung.
    let bytes = Zeroizing::new(
        base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &cleaned_secret)
            .ok_or_else(|| CoreError::invalid_input("Secret ist kein gültiges Base32"))?,
    );
    if bytes.len() < 8 {
        return Err(CoreError::invalid_input("Secret zu kurz"));
    }
    if !(6..=8).contains(&digits) {
        return Err(CoreError::invalid_input("digits muss 6..=8 sein"));
    }
    // B-118/B-136: vorher nur != 0 geprueft - ein otpauth-URI mit period=1
    // oder period=4294967295 passierte unveraendert und widersprach der
    // eigenen IPC-Last-Reduktion (O-1, useCodeTicker.ts). Range deckt die
    // in freier Wildbahn vorkommenden Provider-Werte ab (ManualEntryTab.tsx
    // clamped enger auf 10..=120, hier bewusst grosszuegiger fuer Importe).
    if !(10..=300).contains(&period) {
        return Err(CoreError::invalid_input("period muss zwischen 10 und 300 Sekunden liegen"));
    }
    // B-1: HOTP wird von der TOTP-Engine kategorisch abgelehnt (auth-core/src/totp/engine.rs).
    if kind == OtpKind::Hotp {
        return Err(CoreError::invalid_input("HOTP wird noch nicht unterstützt"));
    }
    Ok(cleaned_secret)
}

impl AccountInput {
    /// Einzige Validierungsquelle für Account-Eingaben - genutzt von
    /// `add_account` (Commit) **und** allen Importern (Vorschau). B-52: vorher
    /// hatte jeder Importer seine eigene, leicht abweichende Kopie dieser
    /// Prüfung; dadurch zeigte die Vorschau Konten, die beim Commit still
    /// verworfen wurden. Eine gemeinsame Funktion macht die Divergenz
    /// strukturell unmöglich. Gibt bei Erfolg das normalisierte Secret zurück.
    pub fn validate(&self) -> CoreResult<Zeroizing<String>> {
        validate_account_fields(
            &self.label,
            &self.issuer,
            &self.secret_b32,
            self.digits,
            self.period,
            self.kind,
        )
    }
}

impl Account {
    /// Dieselben Regeln wie `AccountInput::validate()`, fuer den fertigen
    /// Vault-Eintrag.
    ///
    /// B-153: `restore_accounts_bulk` (Backup-Restore) ist der dritte
    /// Schreibpfad in den Vault, konnte `AccountInput::validate()` aber nicht
    /// aufrufen - falscher Typ - und schrieb dadurch ungeprueft, was im
    /// `.agbak` stand. Ein restauriertes HOTP-Konto landete so dauerhaft im
    /// Vault und zeigte fuer immer "••• •••", ohne Fehlermeldung. Beide Typen
    /// teilen sich jetzt `validate_account_fields`, damit die Regeln nicht an
    /// zwei Stellen auseinanderlaufen koennen (dasselbe Muster, das B-52
    /// zwischen den Importern hergestellt hat).
    pub fn validate(&self) -> CoreResult<Zeroizing<String>> {
        validate_account_fields(
            &self.label,
            &self.issuer,
            &self.secret_b32,
            self.digits,
            self.period,
            self.kind,
        )
    }
}

/// Inhalt des verschlüsselten Vault-Body.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VaultBody {
    #[serde(default)]
    pub accounts: Vec<Account>,
    #[serde(default)]
    pub settings: VaultSettings,
}

/// App-übergreifende Einstellungen (mit verschlüsselt gespeichert).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultSettings {
    pub auto_lock_minutes: u32,
    pub cloud_folder_path: Option<String>,
    pub copy_on_click: bool,
    pub hello_enabled: bool,
}

impl Default for VaultSettings {
    fn default() -> Self {
        Self {
            auto_lock_minutes: 5,
            cloud_folder_path: None,
            copy_on_click: true,
            hello_enabled: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initials_basic() {
        assert_eq!(derive_initials("Google", ""), "GO");
        assert_eq!(derive_initials("GitHub", "alice"), "GI");
        assert_eq!(derive_initials("Acme Inc", "u"), "AI");
        assert_eq!(derive_initials("", "alice@example.com"), "AL");
        assert_eq!(derive_initials("", ""), "??");
    }

    #[test]
    fn color_is_stable_hex() {
        let c = derive_color("GitHub", "alice");
        assert!(c.starts_with('#') && c.len() == 7);
        assert_eq!(c, derive_color("github", "ALICE")); // case-insensitive
    }

    fn valid_totp_input() -> AccountInput {
        AccountInput {
            label: "alice".into(),
            issuer: "GitHub".into(),
            secret_b32: Zeroizing::new("JBSWY3DPEHPK3PXP".into()),
            algorithm: AlgorithmKind::Sha1,
            digits: 6,
            period: 30,
            kind: OtpKind::Totp,
            counter: 0,
        }
    }

    #[test]
    fn validate_accepts_valid_totp_input() {
        assert!(valid_totp_input().validate().is_ok());
    }

    #[test]
    fn validate_rejects_hotp_at_write_boundary() {
        // B-1: unabhaengig davon, ueber welchen Pfad ein HOTP-Konto hier
        // ankommt (Formular, Import, .agbak-Restore) - add_account/
        // add_accounts_bulk sind der einzige Schreibpfad in den Vault und
        // muessen HOTP zentral ablehnen, nicht nur die Importer.
        let mut input = valid_totp_input();
        input.kind = OtpKind::Hotp;
        assert!(input.validate().is_err());
    }

    #[test]
    fn validate_normalises_padded_and_dashed_secret() {
        // B-52: Base32-Padding/Bindestriche aus Provider-QR-Codes muessen
        // dieselbe Normalisierung durchlaufen wie bei add_account, sonst
        // zeigt die Import-Vorschau ein Konto, das beim Commit verschwindet.
        let mut input = valid_totp_input();
        input.secret_b32 = Zeroizing::new("jbsw y3dp-ehpk 3pxp=".into());
        assert_eq!(input.validate().unwrap().as_str(), "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn validate_rejects_secret_too_short() {
        let mut input = valid_totp_input();
        input.secret_b32 = Zeroizing::new("AAAA".into());
        assert!(input.validate().is_err());
    }

    #[test]
    fn validate_rejects_empty_label_and_issuer() {
        let mut input = valid_totp_input();
        input.label = "".into();
        input.issuer = "".into();
        assert!(input.validate().is_err());
    }

    #[test]
    fn validate_rejects_digits_out_of_range() {
        let mut input = valid_totp_input();
        input.digits = 9;
        assert!(input.validate().is_err());
    }

    #[test]
    fn validate_rejects_zero_period() {
        let mut input = valid_totp_input();
        input.period = 0;
        assert!(input.validate().is_err());
    }

    #[test]
    fn validate_rejects_overlong_label_or_issuer() {
        let mut input = valid_totp_input();
        input.label = "A".repeat(MAX_NAME_CHARS + 1);
        assert!(input.validate().is_err());

        let mut input = valid_totp_input();
        input.issuer = "A".repeat(MAX_NAME_CHARS + 1);
        assert!(input.validate().is_err());
    }

    #[test]
    fn validate_accepts_label_and_issuer_at_the_limit() {
        let mut input = valid_totp_input();
        input.label = "A".repeat(MAX_NAME_CHARS);
        input.issuer = "A".repeat(MAX_NAME_CHARS);
        assert!(input.validate().is_ok());
    }
}
