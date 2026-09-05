//! Vault-Format und Sealing — der verschlüsselte Umschlag um den Vault-Body.
//!
//! O-3 Schritt 3d. Hier liegt ausschließlich Bytes-zu-Bytes-Logik: KEK
//! ableiten, MasterKey wrappen/entpacken, Body versiegeln/öffnen. Kein
//! Dateisystem, kein Pfad, kein OS — das Laden und Speichern der Datei
//! bleibt in `src-tauri/src/vault/storage.rs`.
//!
//! Die Trennung ist der Punkt: Tauri-App und eine künftige Chrome-Extension
//! teilen sich damit **ein** Vault-Format statt zweier Implementierungen, die
//! auseinanderlaufen können. Genau deshalb gehört der Umschlag hierher und
//! nicht in die App.
//!
//! Datei-Layout (`vault.dat`, JSON):
//! ```json
//! {
//!   "version": 1,
//!   "kdf":  { "m_cost": 65536, "t_cost": 3, "p_cost": 4 },
//!   "salt": "<base64>",
//!   "wrapped_master": { "nonce": "...", "ct": "..." },  // KEK -> MasterKey
//!   "body":           { "nonce": "...", "ct": "..." }   // MasterKey -> VaultBody
//! }
//! ```
//!
//! **Formatkompatibilität ist hier eine harte Grenze.** Die AAD-Strings, das
//! Base64-Alphabet, die JSON-Feldnamen und die KDF-Vorgaben sind Teil des
//! Dateiformats: Wer sie ändert, macht jeden existierenden Vault unlesbar.
//! Der Golden-Vault-Test in diesem Modul ist die einzige Absicherung, die
//! das merkt — alle Roundtrip-Tests bleiben bei einer konsistenten Änderung
//! grün.

use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{
    aead_open, aead_seal, derive_key, derive_key_legacy_unnormalised, is_password_nfc,
    AeadCiphertext, KdfParams, AEAD_KEY_LEN, SALT_LEN,
};
use crate::error::{CoreError, CoreResult};
use crate::migration::migrate_body;
use crate::model::VaultBody;

/// Aktuelle Version des Datei-Umschlags.
pub const VAULT_VERSION: u8 = 1;

/// Mindestlaenge des Master-Passworts in Zeichen.
///
/// B-105: Die UI kommuniziert diese Regel seit jeher als verbindlich
/// (SetupScreen und ChangePasswordModal: "Mindestens 8 Zeichen"), das
/// Backend prueft sie aber nie - ein direkter IPC-Aufruf legte einen Vault
/// mit einem 1-Zeichen-Passwort an. Dieselbe Klasse wie B-53/B-65: eine als
/// Geschaeftsregel kommunizierte Grenze gehoert an die Schreibgrenze, nicht
/// nur ins Frontend.
pub const MIN_MASTER_PASSWORD_CHARS: usize = 8;

/// On-Disk-Repräsentation der Vault-Datei.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultFile {
    pub version: u8,
    pub kdf: KdfParams,
    /// Base64 des 16-Byte-Salts.
    pub salt: String,
    pub wrapped_master: AeadCiphertext,
    pub body: AeadCiphertext,
}

fn b64() -> base64::engine::GeneralPurpose {
    use base64::engine::general_purpose;
    general_purpose::URL_SAFE_NO_PAD
}

fn encode(bytes: &[u8]) -> String {
    use base64::Engine;
    b64().encode(bytes)
}

fn decode(s: &str) -> CoreResult<Vec<u8>> {
    use base64::Engine;
    b64()
        .decode(s.as_bytes())
        .map_err(|e| CoreError::VaultFormat(format!("Salt-Decode: {e}")))
}

/// Prueft die Master-Passwort-Policy. Gilt beim SETZEN eines Passworts
/// (`create`, `change_password`), bewusst NICHT beim Pruefen (`unlock`) -
/// ein bestehender Vault mit kuerzerem Passwort aus einer aelteren Version
/// muss entsperrbar bleiben, sonst waere der Fix selbst ein Aussperren.
///
/// Zaehlt Unicode-Scalars (`chars()`), nicht Bytes - konsistent mit
/// `MAX_NAME_CHARS` und mit der UI-Aussage "Zeichen". Gegenueber dem
/// Frontend (`password.length`, UTF-16-Code-Units) ist das bei Zeichen
/// ausserhalb der BMP minimal strenger; das ist die richtige Richtung.
fn require_master_password_policy(password: &str) -> CoreResult<()> {
    if password.is_empty() {
        return Err(CoreError::invalid_input("Passwort darf nicht leer sein"));
    }
    if password.chars().count() < MIN_MASTER_PASSWORD_CHARS {
        return Err(CoreError::invalid_input(format!(
            "Master-Passwort muss mindestens {MIN_MASTER_PASSWORD_CHARS} Zeichen lang sein"
        )));
    }
    Ok(())
}

impl VaultFile {
    /// Initialisiert einen neuen Vault mit dem Master-Passwort.
    /// Erzeugt einen zufälligen 32-Byte-`MasterKey`, wrapt ihn unter dem KEK.
    /// Liefert den frischen `MasterKey` zurück (für sofortige Nutzung im RAM).
    pub fn create(
        password: &str,
        body: &VaultBody,
    ) -> CoreResult<(Self, Zeroizing<[u8; AEAD_KEY_LEN]>)> {
        require_master_password_policy(password)?;
        let kdf = KdfParams::default();
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let kek = derive_key(password, &salt, kdf)?;

        // Frischen MasterKey würfeln.
        let mut master = Zeroizing::new([0u8; AEAD_KEY_LEN]);
        OsRng.fill_bytes(master.as_mut_slice());

        let wrapped_master = aead_seal(kek.as_slice(), master.as_slice(), b"vault-master-v1")?;
        // B-104: das serialisierte JSON enthaelt saemtliche TOTP-Secrets im
        // Klartext. Ohne Zeroizing bliebe dieser Puffer nach dem Verschluesseln
        // unueberschrieben im Heap liegen - siehe auch reseal_body.
        let body_json = Zeroizing::new(
            serde_json::to_vec(body)
                .map_err(|e| CoreError::Crypto(format!("Body-Serialisierung: {e}")))?,
        );
        let body_ct = aead_seal(master.as_slice(), &body_json, b"vault-body-v1")?;

        let file = Self {
            version: VAULT_VERSION,
            kdf,
            salt: encode(&salt),
            wrapped_master,
            body: body_ct,
        };
        Ok((file, master))
    }

    /// Entsperrt den Vault mit dem Master-Passwort.
    /// Gibt den entsiegelten Body und den `MasterKey` zurück.
    ///
    /// B-106: Probiert zuerst die NFC-normalisierte Ableitung. Scheitert die
    /// mit `DecryptFailed` UND war die Eingabe nicht ohnehin schon NFC,
    /// folgt ein zweiter Versuch mit den Rohbytes - so bleiben Vaults
    /// entsperrbar, die vor diesem Fix mit einem Nicht-ASCII-Passwort
    /// angelegt wurden. Ohne diesen Fallback waere der Fix selbst der
    /// schlimmstmoegliche Fall gewesen: ein unwiederbringlich ausgesperrter
    /// Bestandsvault, genau der Schaden, den B-106 verhindern soll.
    ///
    /// Bei ASCII-Passwoertern (dem Normalfall) ist `is_password_nfc` immer
    /// true, der Fallback entfaellt und es bleibt bei einer Argon2-Ableitung.
    ///
    /// B-165: Die frueher hier notierte "bekannte Grenze" (Bestandsvault mit
    /// NFD-Passwort nur mit DERSELBEN Eingabequelle entsperrbar) ist
    /// aufgeloest. `unlock_vault` hebt einen solchen Vault beim ersten
    /// erfolgreichen Entsperren einmalig auf den normalisierten KEK
    /// (`rewrap_master_normalised`) - danach entfaellt der Fallback samt
    /// zweiter Argon2-Ableitung, und der eigentliche B-106-Fall (andere
    /// Eingabequelle, visuell gleiches Passwort) ist auch fuer ihn geloest,
    /// ohne Passwortwechsel. Der Fallback hier bleibt fuer genau diesen
    /// ersten Unlock noetig - und fuer den Fall, dass das Nachziehen auf
    /// Platte fehlschlug.
    pub fn unlock(&self, password: &str) -> CoreResult<(VaultBody, Zeroizing<[u8; AEAD_KEY_LEN]>)> {
        let (body, master, _legacy) = self.unlock_reporting_legacy(password)?;
        Ok((body, master))
    }

    /// B-165: wie [`VaultFile::unlock`], meldet zusaetzlich, ob der
    /// Legacy-Fallback gegriffen hat.
    ///
    /// Ohne diese Information zahlt ein Bestandsvault mit NFD-Passwort bei
    /// JEDEM Entsperrversuch dauerhaft zwei Argon2-Ableitungen (64 MiB,
    /// t=3): erst scheitert die NFC-Ableitung, dann oeffnet die zweite. Der
    /// Aufrufer kann den Vault jetzt einmalig auf den normalisierten KEK
    /// heben - siehe `rewrap_master_normalised`.
    pub fn unlock_reporting_legacy(
        &self,
        password: &str,
    ) -> CoreResult<(VaultBody, Zeroizing<[u8; AEAD_KEY_LEN]>, bool)> {
        match self.unlock_with(password, false) {
            // Der Fallback haengt an GENAU dieser Fehlerart: ein
            // fehlgeschlagenes AEAD-Open (falscher KEK). Ein Formatfehler
            // darf hier nicht zu einem zweiten, sinnlosen Argon2-Lauf
            // fuehren.
            Err(CoreError::DecryptFailed) if !is_password_nfc(password) => self
                .unlock_with(password, true)
                .map(|(b, m)| (b, m, true)),
            other => other.map(|(b, m)| (b, m, false)),
        }
    }

    /// B-165: Hebt einen Bestandsvault einmalig auf den normalisierten KEK.
    ///
    /// Wrappt den (unveraenderten) MasterKey unter dem NFC-normalisierten
    /// Passwort neu. Danach oeffnet der Vault beim ersten Versuch, der
    /// Legacy-Fallback entfaellt dauerhaft - und die im `unlock`-Kommentar
    /// notierte "bekannte Grenze" ist aufgeloest: der Vault ist ab dann auch
    /// mit einer ANDEREN Eingabequelle entsperrbar, die dasselbe Passwort
    /// visuell gleich, aber anders normalisiert liefert. Das ist der
    /// eigentliche B-106-Fall, der fuer Bestandsvaults bisher erst nach
    /// einem Passwortwechsel geloest war.
    ///
    /// Der MasterKey selbst bleibt gleich - der Body muss NICHT neu
    /// verschluesselt werden, und ein bestehendes Hello-Sidecar bleibt
    /// gueltig (es ist mit dem Hello-WrapKey verschluesselt, nicht mit dem
    /// KEK).
    ///
    /// Der Salt wird bewusst beibehalten: er ist weiterhin zufaellig und
    /// einmalig, und ein Wechsel braechte keinen Sicherheitsgewinn, wuerde
    /// aber eine zweite Fehlerquelle in einen Pfad einbauen, der beim
    /// Entsperren laeuft.
    pub fn rewrap_master_normalised(
        &mut self,
        password: &str,
        master: &[u8; AEAD_KEY_LEN],
    ) -> CoreResult<()> {
        let salt = decode(&self.salt)?;
        if salt.len() != SALT_LEN {
            return Err(CoreError::VaultFormat("Salt-Länge ungültig".into()));
        }
        let kek = derive_key(password, &salt, self.kdf)?;
        self.wrapped_master = aead_seal(kek.as_slice(), master.as_slice(), b"vault-master-v1")?;
        Ok(())
    }

    fn unlock_with(
        &self,
        password: &str,
        legacy_unnormalised: bool,
    ) -> CoreResult<(VaultBody, Zeroizing<[u8; AEAD_KEY_LEN]>)> {
        let salt = decode(&self.salt)?;
        if salt.len() != SALT_LEN {
            return Err(CoreError::VaultFormat("Salt-Länge ungültig".into()));
        }
        let kek = if legacy_unnormalised {
            derive_key_legacy_unnormalised(password, &salt, self.kdf)?
        } else {
            derive_key(password, &salt, self.kdf)?
        };
        let master_bytes = aead_open(kek.as_slice(), &self.wrapped_master, b"vault-master-v1")?;
        if master_bytes.len() != AEAD_KEY_LEN {
            return Err(CoreError::VaultFormat("MasterKey-Länge ungültig".into()));
        }
        let mut master = Zeroizing::new([0u8; AEAD_KEY_LEN]);
        master.copy_from_slice(&master_bytes);
        let body_bytes = aead_open(master.as_slice(), &self.body, b"vault-body-v1")?;
        // Body durch das Migrations-Framework leiten. Bei aktueller Version ein
        // Passthrough; ältere Vaults werden auf das aktuelle Schema gehoben.
        let body = migrate_body(self.version, &body_bytes)?;
        Ok((body, master))
    }

    /// Schreibt einen geänderten Body unter dem aktuellen `MasterKey`.
    pub fn reseal_body(&mut self, master: &[u8], body: &VaultBody) -> CoreResult<()> {
        // B-104: der volumenstaerkste Klartext-Puffer der ganzen App - diese
        // Funktion laeuft bei JEDER Mutation (Konto anlegen/loeschen/umbenennen/
        // sortieren, Bulk-Import, Restore, Settings-Schreibvorgang nach einem
        // Backup-Import). Jeder Aufruf serialisiert den kompletten Vault
        // inklusive aller Secrets nach JSON; ohne Zeroizing hinterliesse jede
        // dieser Operationen eine vollstaendige Klartext-Kopie im freigegebenen
        // Heap.
        let bytes = Zeroizing::new(
            serde_json::to_vec(body)
                .map_err(|e| CoreError::Crypto(format!("Body-Serialisierung: {e}")))?,
        );
        self.body = aead_seal(master, &bytes, b"vault-body-v1")?;
        Ok(())
    }

    /// Wechselt das Master-Passwort: erzeugt neuen Salt, neuen KEK, wrappt
    /// den existierenden `MasterKey` neu. Body bleibt unangetastet.
    pub fn change_password(&mut self, old: &str, new: &str) -> CoreResult<()> {
        require_master_password_policy(new)?;
        let (_body, master) = self.unlock(old)?;
        let kdf = KdfParams::default();
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let kek = derive_key(new, &salt, kdf)?;
        self.kdf = kdf;
        self.salt = encode(&salt);
        self.wrapped_master = aead_seal(kek.as_slice(), master.as_slice(), b"vault-master-v1")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Account, AlgorithmKind, OtpKind, VaultBody};

    fn sample_body() -> VaultBody {
        VaultBody {
            accounts: vec![Account {
                id: "abc".into(),
                label: "alice@example.com".into(),
                issuer: "GitHub".into(),
                algorithm: AlgorithmKind::Sha1,
                digits: 6,
                period: 30,
                secret_b32: Zeroizing::new("JBSWY3DPEHPK3PXP".into()),
                kind: OtpKind::Totp,
                counter: 0,
                order: 0,
                created_at: "2026-04-28T10:00:00Z".into(),
            }],
            settings: Default::default(),
        }
    }

    /// Ein **echter**, mit dem damaligen Code erzeugter Vault, eingefroren als
    /// Fixture. Er muss sich mit `GOLDEN_PW` oeffnen lassen - und zwar ueber
    /// jeden kuenftigen Umbau des Sealing-Codes hinweg.
    ///
    /// Warum dieser Test noetig ist, obwohl es zehn andere gibt: alle anderen
    /// verschluesseln und entschluesseln im SELBEN Lauf. Wuerde jemand die
    /// AAD-Strings (`vault-master-v1`/`vault-body-v1`), das Base64-Alphabet
    /// (URL_SAFE_NO_PAD), die Feldnamen des JSON-Umschlags oder die
    /// KDF-Vorgaben aendern - konsistent in beide Richtungen -, blieben sie
    /// ausnahmslos gruen, waehrend JEDER auf Platte liegende Vault
    /// unlesbar wuerde. Genau diesen Fehler faengt nur ein Ciphertext, der
    /// aelter ist als die Aenderung.
    ///
    /// Gemessen, nicht behauptet: mit mutiertem AAD (`vault-body-v1` ->
    /// `-v2`) blieben 12 der 13 Sealing-Tests gruen, nur dieser fiel.
    ///
    /// Schlaegt dieser Test fehl, ist das Datei-Format gebrochen. Dann ist
    /// nicht der Test anzupassen, sondern die Aenderung zurueckzunehmen.
    const GOLDEN_VAULT: &str = r#"{"version":1,"kdf":{"m_cost":65536,"t_cost":3,"p_cost":4},"salt":"WI76kLXbZLQDa1cdOztJ0Q","wrapped_master":{"nonce":"Rv4WKKBGaP3kOX9vlWckZ4DalyXdgPxy","ct":"D_UFsR0AOGjRXbSOeIqET_wld4fevFC1OQ9hiNs27p82wHun6HSiZrPJ6lsrVoac"},"body":{"nonce":"O-U41SQ9gZeKOV0pV9hGwYDHg_eC2dp5","ct":"Y97RGdRN9ZitRfLCBDJ9FS2CI5c4F8_dvi1GxOZC_TGv3ffLWT1BJN-WXgBbYCFkYri0JS-AZf0F-4v9frX0e2xELSlYUaKW6tLVLD-A5u2kYCSG75zlmB-j7POOyXDu5HDYhZQF0T7CMbN4_Jo72JzRTtKH2f9bvouw9JxmpsBsbA5FTC_7lo6Y1ul-RuiR0xiIWlGvEh_A_h-pOROIzgeTrtHSMMWsdKZY-tDzpI7gK0jFqRluzNL8nAYZN_9YE0ga8ThAqG2SjnpWnBPncbfk91ZMTSB-5FEoylnERtNUiJgs6xDhJnCp-zk3r4Os00NJ_P1S35E_SEuL82YSvbhERGjX0aELp92uIYGgItMx5df7LhVrHjXkPDzk8sl2U2FThoyfCcnCjEK3gVUwdh7OoUCM6TTliuax_txe3C-lZhyU0OrqoMvIihYavJ6p3luaqCSTig"}}"#;

    const GOLDEN_PW: &str = "goldenes-passwort";

    #[test]
    fn ein_bestehender_vault_von_der_platte_bleibt_lesbar() {
        let file: VaultFile =
            serde_json::from_str(GOLDEN_VAULT).expect("Fixture muss deserialisieren");
        let (body, _master) = file
            .unlock(GOLDEN_PW)
            .expect("Bestandsvault MUSS sich weiterhin oeffnen lassen");

        assert_eq!(body.accounts.len(), 1);
        assert_eq!(body.accounts[0].issuer, "GitHub");
        assert_eq!(body.accounts[0].label, "alice@example.com");
        // Das Secret ist der eigentliche Wert - waere es beschaedigt, kaeme
        // der Nutzer nicht mehr in sein Konto.
        assert_eq!(body.accounts[0].secret_b32.as_str(), "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn der_geschriebene_umschlag_behaelt_seine_form() {
        // Die andere Haelfte der Kompatibilitaet: Lesen allein genuegt
        // nicht. Wuerde sich die Serde-Form aendern - ein umbenanntes Feld,
        // eine andere Verschachtelung, ein zusaetzliches Attribut -, liesse
        // sich der Bestandsvault zwar noch oeffnen, aber beim naechsten
        // Speichern schriebe die App einen Umschlag, den nichts anderes
        // mehr liest. Der Schaden traete erst nach dem naechsten
        // Kontowechsel auf, also lange nach der Ursache.
        //
        // Deshalb hier hin und zurueck: Was rausgeht, muss zeichengleich
        // dem entsprechen, was reinkam.
        let file: VaultFile = serde_json::from_str(GOLDEN_VAULT).unwrap();
        let wieder = serde_json::to_string(&file).unwrap();
        assert_eq!(
            wieder, GOLDEN_VAULT,
            "Der serialisierte Umschlag weicht vom Bestandsformat ab"
        );
    }

    #[test]
    fn der_goldene_vault_oeffnet_nicht_mit_falschem_passwort() {
        // Gegenprobe: der Test oben darf nicht deshalb gruen sein, weil
        // `unlock` alles durchwinkt.
        let file: VaultFile = serde_json::from_str(GOLDEN_VAULT).unwrap();
        assert!(matches!(
            file.unlock("goldenes-passwort!").unwrap_err(),
            CoreError::DecryptFailed
        ));
    }

    /// "Passéwort!" in beiden Unicode-Normalformen - visuell identisch,
    /// als Bytes verschieden (siehe auth-core/src/crypto/kdf.rs).
    const NFC_PW: &str = "Pass\u{00e9}wort!";
    const NFD_PW: &str = "Passe\u{0301}wort!";

    /// Erzeugt einen Vault so, wie ihn die App VOR dem B-106-Fix angelegt
    /// haette: KEK aus den unnormalisierten Rohbytes. Spiegelt `create`,
    /// nur mit der Legacy-Ableitung - anders laesst sich der
    /// Kompatibilitaetsfall nicht ehrlich testen, und ohne diesen Test
    /// waere "Bestandsvaults bleiben lesbar" bloss behauptet.
    fn create_legacy_unnormalised(password: &str, body: &VaultBody) -> CoreResult<VaultFile> {
        let kdf = KdfParams::default();
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let kek = derive_key_legacy_unnormalised(password, &salt, kdf)?;
        let mut master = Zeroizing::new([0u8; AEAD_KEY_LEN]);
        OsRng.fill_bytes(master.as_mut_slice());
        let wrapped_master = aead_seal(kek.as_slice(), master.as_slice(), b"vault-master-v1")?;
        let body_json = Zeroizing::new(serde_json::to_vec(body).unwrap());
        let body_ct = aead_seal(master.as_slice(), &body_json, b"vault-body-v1")?;
        Ok(VaultFile {
            version: VAULT_VERSION,
            kdf,
            salt: encode(&salt),
            wrapped_master,
            body: body_ct,
        })
    }

    #[test]
    fn rewrapping_a_legacy_vault_removes_the_fallback_and_the_known_limit() {
        // B-165: Ein Bestandsvault mit NFD-Passwort zahlt bei jedem Unlock
        // zwei Argon2-Ableitungen - erst scheitert NFC, dann oeffnet der
        // Legacy-Fallback.
        let mut file = create_legacy_unnormalised(NFD_PW, &sample_body()).unwrap();

        // Vorher: Legacy-Fallback ist noetig (das ist die zweite Ableitung).
        let (_b, master, used_legacy) = file.unlock_reporting_legacy(NFD_PW).unwrap();
        assert!(used_legacy, "Bestandsvault MUSS ueber den Fallback oeffnen");

        // Und die im Code notierte "bekannte Grenze": mit der ANDEREN
        // Eingabequelle (visuell gleiches Passwort, NFC statt NFD) geht er
        // gar nicht auf.
        assert!(
            file.unlock(NFC_PW).is_err(),
            "vor dem Re-Wrap darf NFC den Legacy-Vault nicht oeffnen"
        );

        file.rewrap_master_normalised(NFD_PW, &master).unwrap();

        // Nachher 1: oeffnet beim ERSTEN Versuch, kein Fallback mehr.
        let (body, master_after, used_legacy) = file.unlock_reporting_legacy(NFD_PW).unwrap();
        assert!(
            !used_legacy,
            "nach dem Re-Wrap darf kein Fallback mehr noetig sein"
        );

        // Nachher 2: die bekannte Grenze ist aufgeloest - dieselbe Datei
        // oeffnet jetzt auch mit der anderen Eingabequelle. Das ist der
        // eigentliche B-106-Fall.
        assert!(
            file.unlock(NFC_PW).is_ok(),
            "nach dem Re-Wrap muss NFC oeffnen"
        );

        // Der MasterKey ist unveraendert (Body wurde nicht neu
        // verschluesselt, ein Hello-Sidecar bliebe gueltig) ...
        assert_eq!(master_after.as_slice(), master.as_slice());
        // ... und der Inhalt ist unversehrt.
        assert_eq!(body.accounts.len(), 1);
        assert_eq!(body.accounts[0].label, sample_body().accounts[0].label);
    }

    #[test]
    fn nfd_and_nfc_input_unlock_the_same_new_vault() {
        // B-106: der eigentliche Fix. Ein NEU angelegter Vault laesst sich
        // mit beiden Normalformen oeffnen - die Eingabequelle (Tastatur,
        // IME, Passwort-Manager) entscheidet nicht mehr darueber, ob der
        // Nutzer wieder hineinkommt.
        let body = sample_body();
        let (file, _) = VaultFile::create(NFC_PW, &body).unwrap();
        assert!(file.unlock(NFC_PW).is_ok(), "NFC muss oeffnen");
        assert!(file.unlock(NFD_PW).is_ok(), "NFD muss dieselbe Datei oeffnen");
    }

    #[test]
    fn legacy_unnormalised_vault_still_unlocks() {
        // Der Kompatibilitaets-Schutz: ein vor dem Fix mit NFD-Passwort
        // angelegter Vault muss weiterhin aufgehen. Ohne den Fallback in
        // `unlock` waere er unwiederbringlich verloren - der Fix selbst
        // waere dann der schlimmere Schaden gewesen.
        let body = sample_body();
        let file = create_legacy_unnormalised(NFD_PW, &body).unwrap();
        let (decoded, _) = file
            .unlock(NFD_PW)
            .expect("Legacy-Vault muss ueber den Fallback aufgehen");
        assert_eq!(decoded.accounts.len(), 1);
    }

    #[test]
    fn legacy_vault_migrates_to_normalised_on_password_change() {
        // Der dokumentierte Migrationsweg: nach einem Passwortwechsel liegt
        // auch ein Bestandsvault auf der normalisierten Ableitung und
        // profitiert dann voll von B-106 (beide Normalformen oeffnen ihn).
        let body = sample_body();
        let mut file = create_legacy_unnormalised(NFD_PW, &body).unwrap();
        file.change_password(NFD_PW, NFC_PW).unwrap();
        assert!(file.unlock(NFC_PW).is_ok());
        assert!(
            file.unlock(NFD_PW).is_ok(),
            "nach der Migration oeffnet auch die andere Normalform"
        );
    }

    #[test]
    fn wrong_password_still_fails_with_the_legacy_fallback_in_place() {
        // Gegenprobe: der Fallback darf kein Scheunentor sein - ein falsches
        // Passwort scheitert weiterhin, auch wenn es nicht in NFC vorliegt
        // und damit beide Ableitungen durchlaufen werden.
        let body = sample_body();
        let (file, _) = VaultFile::create(NFC_PW, &body).unwrap();
        let err = file.unlock("Falsche\u{0301}s-Passwort").unwrap_err();
        assert!(matches!(err, CoreError::DecryptFailed), "war: {err:?}");
    }

    #[test]
    fn create_and_change_password_enforce_the_minimum_length() {
        // B-105: die UI nennt "mindestens 8 Zeichen" seit jeher als
        // verbindlich, das Backend setzte es nie durch - ein direkter
        // IPC-Aufruf legte einen Vault mit 1-Zeichen-Passwort an.
        let body = sample_body();
        assert!(
            VaultFile::create("kurz", &body).is_err(),
            "4 Zeichen muessen scheitern"
        );
        assert!(VaultFile::create("", &body).is_err(), "leer muss scheitern");
        assert!(
            VaultFile::create("genau8ok", &body).is_ok(),
            "genau 8 muessen reichen"
        );

        let (mut file, _) = VaultFile::create("langgenug1", &body).unwrap();
        assert!(file.change_password("langgenug1", "kurz").is_err());
        assert!(file.change_password("langgenug1", "auch-lang-genug").is_ok());
    }

    #[test]
    fn unlock_does_not_enforce_the_minimum_length() {
        // Bewusste Asymmetrie: die Policy gilt beim SETZEN, nicht beim
        // PRUEFEN. Ein Bestandsvault mit kurzem Passwort aus einer aelteren
        // Version muss entsperrbar bleiben - sonst waere der Fix selbst ein
        // Aussperren.
        let body = sample_body();
        let file = create_legacy_unnormalised("kurz", &body).unwrap();
        assert!(
            file.unlock("kurz").is_ok(),
            "kurzes Bestandspasswort muss weiterhin oeffnen"
        );
    }

    #[test]
    fn create_unlock_roundtrip() {
        let body = sample_body();
        let (file, _master) = VaultFile::create("hunter2!", &body).unwrap();
        let (decoded, _) = file.unlock("hunter2!").unwrap();
        assert_eq!(decoded.accounts.len(), 1);
        assert_eq!(decoded.accounts[0].issuer, "GitHub");
    }

    #[test]
    fn wrong_password_fails() {
        let body = sample_body();
        let (file, _) = VaultFile::create("richtig123", &body).unwrap();
        let err = file.unlock("falsch456").unwrap_err();
        assert!(matches!(err, CoreError::DecryptFailed));
    }

    #[test]
    fn reseal_body_roundtrip() {
        let body = sample_body();
        let (mut file, master) = VaultFile::create("passwort1", &body).unwrap();
        let mut new_body = body.clone();
        new_body.accounts[0].label = "bob@example.com".into();
        file.reseal_body(master.as_slice(), &new_body).unwrap();
        let (decoded, _) = file.unlock("passwort1").unwrap();
        assert_eq!(decoded.accounts[0].label, "bob@example.com");
    }

    #[test]
    fn change_password() {
        let body = sample_body();
        let (mut file, _) = VaultFile::create("altes-pw1", &body).unwrap();
        file.change_password("altes-pw1", "neues-pw1").unwrap();
        assert!(file.unlock("altes-pw1").is_err());
        assert!(file.unlock("neues-pw1").is_ok());
    }
}
