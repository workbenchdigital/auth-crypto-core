//! Parser fuer Fremdformate - reine Bytes/Text-Verarbeitung ohne Datei- oder
//! OS-Zugriff (O-3 Schritt 3).
//!
//! Bewusst NICHT hier: `qr` (Bilddekodierung) und `screen`
//! (Bildschirmaufnahme) bleiben in der App, weil sie Bilddaten und
//! OS-Bildschirmzugriff brauchen. `external_json` liest Dateien - dieses
//! Lesen (Groessenbegrenzung) bleibt in `src-tauri`, nur seine Parse-Schicht
//! liegt hier.

pub mod external_json;
pub mod google_migration;
pub mod otpauth;
pub mod proto_min;
