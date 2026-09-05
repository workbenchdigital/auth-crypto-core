use super::*;

#[test]
fn rejects_wrong_scheme() {
    assert!(parse_google_migration("otpauth://totp/x?secret=y").is_err());
}

#[test]
fn rejects_missing_data() {
    assert!(parse_google_migration("otpauth-migration://offline?nope=1").is_err());
}

#[test]
fn rejects_bad_base64() {
    assert!(parse_google_migration("otpauth-migration://offline?data=!!!!").is_err());
}

// Protobuf-Test-Helper (auch von anderen Tests in diesem Modul genutzt,
// z. B. skips_hotp_entries_in_batch). Wir nutzen dieselben wie in
// proto_min_tests.
fn varint(mut v: u64, out: &mut Vec<u8>) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}
fn ld(field: u32, data: &[u8], out: &mut Vec<u8>) {
    let t = ((field as u64) << 3) | 2;
    varint(t, out);
    varint(data.len() as u64, out);
    out.extend_from_slice(data);
}
fn vint(field: u32, v: u64, out: &mut Vec<u8>) {
    // Wire-Type 0 (varint): tag = field << 3 | 0 → field << 3.
    let t = (field as u64) << 3;
    varint(t, out);
    varint(v, out);
}

#[test]
fn parses_synthetic_payload() {
    // synthetisch erzeugen: eine OtpParameters, secret=DEADBEEF, name="alice", issuer="X"
    let mut inner = Vec::new();
    ld(1, &[0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF], &mut inner);
    ld(2, b"alice", &mut inner);
    ld(3, b"X", &mut inner);
    vint(4, 1, &mut inner);
    vint(5, 1, &mut inner);
    vint(6, 2, &mut inner);

    let mut outer = Vec::new();
    ld(1, &inner, &mut outer);
    vint(2, 1, &mut outer);

    let b64 = base64::engine::general_purpose::STANDARD.encode(&outer);
    let uri = format!("otpauth-migration://offline?data={}", urlencoding(&b64));
    let (res, skipped, batch) = parse_google_migration(&uri).unwrap();
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].issuer, "X");
    assert_eq!(res[0].label, "alice");
    assert_eq!(res[0].digits, 6);
    assert_eq!(res[0].algorithm, AlgorithmKind::Sha1);
    assert!(skipped.is_empty());
    // B-5: kein batch_size-Feld im Fixture -> kein Batch.
    assert!(batch.is_none());
}

#[test]
fn accepts_raw_unencoded_plus_in_data_param() {
    // B-50: '+' ist ein gueltiges Base64-Zeichen und kommt in echten
    // Exporten vor. url::query_pairs() wandelt ein rohes (nicht
    // prozentkodiertes) '+' in ein Leerzeichen um (form-urlencoded-
    // Semantik) - ohne Rueckwandlung schlug der Paste-Pfad mit
    // "Base64: Invalid symbol 32" fehl, obwohl derselbe Inhalt als QR
    // (URI landet dort ueber einen anderen Pfad) scannbar gewesen waere.
    let mut inner = Vec::new();
    // Secret bewusst mit letztem Byte 0x3E gewaehlt: die Standard-
    // Base64-Kodierung dieses Payloads enthaelt dadurch nachweislich
    // ein '+' (per Skript verifiziert) - ohne das waere der Test ein
    // Blindflug, ob der reproduzierte Fall ueberhaupt eintritt.
    ld(1, &[0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0x3E], &mut inner);
    ld(2, b"alice", &mut inner);
    ld(3, b"X", &mut inner);
    vint(4, 1, &mut inner);
    vint(5, 1, &mut inner);
    vint(6, 2, &mut inner);

    let mut outer = Vec::new();
    ld(1, &inner, &mut outer);
    vint(2, 1, &mut outer);

    let b64 = base64::engine::general_purpose::STANDARD.encode(&outer);
    assert!(
        b64.contains('+'),
        "Testpayload enthält kein '+' mehr - Fixture prüfen: {b64}"
    );
    // Bewusst OHNE urlencoding(): genau ein rohes '+' in der Query
    // reproduziert den Bug, wie es ein naiver URI-Zusammenbau liefert.
    let uri = format!("otpauth-migration://offline?data={}", b64);
    let (res, _skipped, batch) = parse_google_migration(&uri).unwrap();
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].issuer, "X");
    assert!(batch.is_none());
}

#[test]
fn skips_hotp_entries_in_batch() {
    // HOTP wird von der TOTP-Engine kategorisch abgelehnt (B-1) - ein
    // importiertes HOTP-Konto wuerde nie einen Code liefern, deshalb wird
    // es schon beim Migrations-Import uebersprungen. Das TOTP-Konto im
    // selben Batch bleibt unberuehrt.
    fn otp_param(issuer: &[u8], otp_type: u64) -> Vec<u8> {
        let mut inner = Vec::new();
        ld(1, &[0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF], &mut inner);
        ld(2, b"alice", &mut inner);
        ld(3, issuer, &mut inner);
        vint(4, 1, &mut inner);
        vint(5, 1, &mut inner);
        vint(6, otp_type, &mut inner);
        inner
    }
    let mut outer = Vec::new();
    ld(1, &otp_param(b"HotpAcc", 1), &mut outer); // HOTP
    ld(1, &otp_param(b"Keep", 2), &mut outer); // TOTP
    vint(2, 1, &mut outer);

    let b64 = base64::engine::general_purpose::STANDARD.encode(&outer);
    let uri = format!("otpauth-migration://offline?data={}", urlencoding(&b64));
    let (res, skipped, batch) = parse_google_migration(&uri).unwrap();
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].issuer, "Keep");
    // B-55: der Skip-Grund fuer das HOTP-Konto muss die UI erreichen -
    // vorher hatte google_migration.rs ueberhaupt kein Logging dafuer.
    assert_eq!(skipped.len(), 1);
    assert!(skipped[0].contains("HOTP"), "{skipped:?}");
    assert!(batch.is_none());
}

#[test]
fn skips_unspecified_or_unknown_otp_type() {
    // B-135: otp_type==0 (proto3-Default bei fehlendem Feld) oder ein
    // anderer unbekannter Wert wurde vorher stillschweigend zu TOTP -
    // jetzt strikt gematcht wie bei Aegis/2FAS.
    fn otp_param(issuer: &[u8], otp_type: u64) -> Vec<u8> {
        let mut inner = Vec::new();
        ld(1, &[0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF], &mut inner);
        ld(2, b"alice", &mut inner);
        ld(3, issuer, &mut inner);
        vint(4, 1, &mut inner);
        vint(5, 1, &mut inner);
        vint(6, otp_type, &mut inner);
        inner
    }
    let mut outer = Vec::new();
    ld(1, &otp_param(b"Unspecified", 0), &mut outer);
    ld(1, &otp_param(b"Unknown", 5), &mut outer);
    ld(1, &otp_param(b"Keep", 2), &mut outer); // TOTP
    vint(2, 1, &mut outer);

    let b64 = base64::engine::general_purpose::STANDARD.encode(&outer);
    let uri = format!("otpauth-migration://offline?data={}", urlencoding(&b64));
    let (res, skipped, _batch) = parse_google_migration(&uri).unwrap();
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].issuer, "Keep");
    assert_eq!(skipped.len(), 2);
    assert!(skipped.iter().all(|s| s.contains("Kontotyp unbekannt")), "{skipped:?}");
}

#[test]
fn skips_secret_too_short() {
    // B-52: Die Secret-Mindestlaenge wird jetzt zentral ueber
    // AccountInput::validate geprueft, dieselbe Regel wie add_account -
    // vorher durfte ein zu kurzes Secret in die Vorschau, verschwand
    // beim Commit aber stillschweigend.
    fn otp_param(issuer: &[u8], secret: &[u8]) -> Vec<u8> {
        let mut inner = Vec::new();
        ld(1, secret, &mut inner);
        ld(2, b"alice", &mut inner);
        ld(3, issuer, &mut inner);
        vint(4, 1, &mut inner);
        vint(5, 1, &mut inner);
        vint(6, 2, &mut inner); // TOTP
        inner
    }
    let mut outer = Vec::new();
    ld(1, &otp_param(b"TooShort", &[0xDE, 0xAD, 0xBE, 0xEF]), &mut outer);
    ld(
        1,
        &otp_param(b"Keep", &[0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF]),
        &mut outer,
    );
    vint(2, 1, &mut outer);

    let b64 = base64::engine::general_purpose::STANDARD.encode(&outer);
    let uri = format!("otpauth-migration://offline?data={}", urlencoding(&b64));
    let (res, skipped, batch) = parse_google_migration(&uri).unwrap();
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].issuer, "Keep");
    assert_eq!(skipped.len(), 1);
    assert!(batch.is_none());
}

#[test]
fn returns_batch_info_when_batch_size_greater_than_one() {
    // B-5: batch_size/batch_index/batch_id werden jetzt gelesen, statt
    // stillschweigend verworfen zu werden - Grundlage fuer die
    // Akkumulation mehrerer QR-Codes im Staging (commands/import.rs).
    let mut inner = Vec::new();
    ld(1, &[0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF], &mut inner);
    ld(2, b"alice", &mut inner);
    ld(3, b"X", &mut inner);
    vint(4, 1, &mut inner);
    vint(5, 1, &mut inner);
    vint(6, 2, &mut inner);

    let mut outer = Vec::new();
    ld(1, &inner, &mut outer);
    vint(2, 1, &mut outer); // version
    vint(3, 2, &mut outer); // batch_size=2
    vint(4, 0, &mut outer); // batch_index=0
    vint(5, 99, &mut outer); // batch_id=99

    let b64 = base64::engine::general_purpose::STANDARD.encode(&outer);
    let uri = format!("otpauth-migration://offline?data={}", urlencoding(&b64));
    let (res, _skipped, batch) = parse_google_migration(&uri).unwrap();
    assert_eq!(res.len(), 1);
    let batch = batch.expect("batch_size=2 sollte Some(MigrationBatchInfo) liefern");
    assert_eq!(batch.batch_id, 99);
    assert_eq!(batch.batch_size, 2);
    assert_eq!(batch.batch_index, 0);
}

fn urlencoding(s: &str) -> String {
    // simpler URL-encoder für die Tests (= -> %3D, + -> %2B, / -> %2F)
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => out.push(c),
            _ => out.push_str(&format!("%{:02X}", c as u32)),
        }
    }
    out
}
