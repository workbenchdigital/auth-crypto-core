use super::*;

const SECRET: &str = "JBSWY3DPEHPK3PXP";

fn aegis(entries: &str) -> String {
    format!(
        r#"{{"version":1,"header":{{"slots":null,"params":null}},
            "db":{{"version":3,"entries":[{entries}],"groups":[]}}}}"#
    )
}

// ── Aegis ────────────────────────────────────────────────

#[test]
fn aegis_plain_totp() {
    let raw = aegis(&format!(
        r#"{{"type":"totp","uuid":"x","name":"alice@example.com","issuer":"GitHub",
             "note":"","icon":null,"icon_mime":null,"favorite":false,
             "info":{{"secret":"{SECRET}","algo":"SHA256","digits":8,"period":60}},
             "groups":[]}}"#
    ));
    let (accs, _skipped) = parse_json_backup(&raw).unwrap();
    assert_eq!(accs.len(), 1);
    assert_eq!(accs[0].issuer, "GitHub");
    assert_eq!(accs[0].label, "alice@example.com");
    assert_eq!(accs[0].secret_b32.as_str(), SECRET);
    assert_eq!(accs[0].algorithm, AlgorithmKind::Sha256);
    assert_eq!(accs[0].digits, 8);
    assert_eq!(accs[0].period, 60);
    assert_eq!(accs[0].kind, OtpKind::Totp);
}

#[test]
fn aegis_skips_hotp_but_keeps_totp() {
    // HOTP wird von der TOTP-Engine kategorisch abgelehnt (B-1) - ein
    // importiertes HOTP-Konto wuerde nie einen Code liefern. Deshalb wird
    // es schon an der Importgrenze uebersprungen statt gespeichert.
    let raw = aegis(&format!(
        r#"{{"type":"hotp","name":"bob","issuer":"Acme",
             "info":{{"secret":"{SECRET}","algo":"SHA1","digits":6,"counter":42}}}},
           {{"type":"totp","name":"ok","issuer":"Keep","info":{{"secret":"{SECRET}"}}}}"#
    ));
    let (accs, skipped) = parse_json_backup(&raw).unwrap();
    assert_eq!(accs.len(), 1);
    assert_eq!(accs[0].issuer, "Keep");
    // B-55: der Skip-Grund muss die UI erreichen, nicht nur ein Log.
    assert_eq!(skipped.len(), 1);
    assert!(skipped[0].contains("nicht unterstützt"), "{skipped:?}");
}

#[test]
fn aegis_rejects_newer_than_known_db_version() {
    // B-54: eine hoehere db.version als die verifiziert unterstuetzte
    // koennte Felder anders belegen - lieber ablehnen als still falsch
    // zu mappen (gleiche Haltung wie die Aegis-Referenzimplementierung).
    let raw = r#"{"version":1,"header":{"slots":null,"params":null},
        "db":{"version":99,"entries":[],"groups":[]}}"#;
    let err = parse_json_backup(raw).unwrap_err().to_string();
    assert!(err.contains("Unbekanntes Aegis-Export-Format"), "{err}");
}

#[test]
fn aegis_encrypted_db_string_is_rejected() {
    let raw = r#"{"version":1,
        "header":{"slots":[{"type":1,"uuid":"a"}],"params":{"nonce":"00","tag":"11"}},
        "db":"Zm9vYmFyCg=="}"#;
    let err = parse_json_backup(raw).unwrap_err().to_string();
    assert!(err.contains("passwortgeschützt"), "{err}");
}

#[test]
fn aegis_slots_present_but_db_object_is_rejected() {
    // Verschleierte Variante: db sieht harmlos aus, slots verrät es.
    let raw = r#"{"version":1,"header":{"slots":[],"params":null},
        "db":{"version":3,"entries":[],"groups":[]}}"#;
    let err = parse_json_backup(raw).unwrap_err().to_string();
    assert!(err.contains("passwortgeschützt"), "{err}");
}

#[test]
fn aegis_skips_unsupported_types_but_keeps_totp() {
    let raw = aegis(&format!(
        r#"{{"type":"steam","name":"s","issuer":"Steam","info":{{"secret":"{SECRET}"}}}},
           {{"type":"motp","name":"m","issuer":"M","info":{{"secret":"{SECRET}","algo":"MD5"}}}},
           {{"type":"yandex","name":"y","issuer":"Y","info":{{"secret":"{SECRET}"}}}},
           {{"type":"totp","name":"ok","issuer":"Keep","info":{{"secret":"{SECRET}"}}}}"#
    ));
    let (accs, skipped) = parse_json_backup(&raw).unwrap();
    assert_eq!(accs.len(), 1);
    assert_eq!(accs[0].issuer, "Keep");
    // B-55: drei nicht unterstützte Typen -> drei Skip-Gründe.
    assert_eq!(skipped.len(), 3);
    assert!(skipped.iter().all(|s| s.contains("nicht unterstützt")), "{skipped:?}");
}

#[test]
fn aegis_skips_invalid_entries_instead_of_failing_file() {
    let raw = aegis(&format!(
        r#"{{"type":"totp","name":"a","issuer":"A","info":{{"secret":"nicht base32!!"}}}},
           {{"type":"totp","name":"b","issuer":"B","info":{{"secret":"{SECRET}","digits":99}}}},
           {{"type":"totp","name":"c","issuer":"C","info":{{"secret":"{SECRET}","period":0}}}},
           {{"type":"totp","name":"d","issuer":"D","info":{{"secret":"{SECRET}","digits":-1}}}},
           {{"type":"totp","name":"e","issuer":"E","info":{{"secret":"{SECRET}","period":-30}}}},
           {{"type":"totp","name":"f","issuer":"F","info":{{"secret":"AAAA"}}}},
           {{"type":"totp","name":"","issuer":"","info":{{"secret":"{SECRET}"}}}},
           {{"type":"totp","name":"ok","issuer":"Good","info":{{"secret":"{SECRET}","counter":-5}}}}"#
    ));
    let (accs, skipped) = parse_json_backup(&raw).unwrap();
    assert_eq!(accs.len(), 1);
    assert_eq!(accs[0].issuer, "Good");
    assert_eq!(accs[0].counter, 0); // negativer Counter → 0, kein Panic
    // B-55: 7 der 8 Einträge sind ungültig -> 7 Skip-Gründe, keiner leer.
    assert_eq!(skipped.len(), 7);
    assert!(skipped.iter().all(|s| !s.is_empty()));
}

#[test]
fn aegis_tolerates_nulls_and_unknown_fields() {
    let raw = aegis(&format!(
        r#"{{"type":"totp","name":null,"issuer":"OnlyIssuer","note":null,
             "brandNewFieldFromFutureVersion":{{"a":[1,2,3]}},
             "info":{{"secret":"{SECRET}","algo":null,"digits":null,"period":null}}}}"#
    ));
    let (accs, _skipped) = parse_json_backup(&raw).unwrap();
    assert_eq!(accs[0].issuer, "OnlyIssuer");
    assert_eq!(accs[0].label, "");
    assert_eq!(accs[0].digits, 6);
    assert_eq!(accs[0].period, 30);
}

#[test]
fn aegis_without_usable_entries_errors() {
    let err = parse_json_backup(&aegis("")).unwrap_err().to_string();
    assert!(err.contains("keine importierbaren"), "{err}");
}

#[test]
fn aegis_db_with_wrong_shape_errors_cleanly() {
    let raw = r#"{"version":1,"header":null,"db":{"entries":"nicht-array"}}"#;
    let err = parse_json_backup(raw).unwrap_err().to_string();
    assert!(err.starts_with("Aegis-Import:"), "{err}");
}

// ── 2FAS ─────────────────────────────────────────────────

#[test]
fn twofas_plain_totp() {
    let raw = format!(
        r#"{{"schemaVersion":4,"appVersionCode":5000000,"appOrigin":"android",
            "services":[{{"name":"Deno","secret":"{SECRET}","updatedAt":1708958115316,
              "otp":{{"label":"Mason","account":"Mason","issuer":"Deno","digits":6,
                      "period":30,"algorithm":"SHA1","tokenType":"TOTP","source":"Link"}},
              "order":{{"position":0}}}}],
            "groups":[]}}"#
    );
    let (accs, _skipped) = parse_json_backup(&raw).unwrap();
    assert_eq!(accs.len(), 1);
    assert_eq!(accs[0].issuer, "Deno");
    assert_eq!(accs[0].label, "Mason");
    assert_eq!(accs[0].secret_b32.as_str(), SECRET);
    assert_eq!(accs[0].kind, OtpKind::Totp);
}

#[test]
fn twofas_skips_hotp_but_keeps_totp_with_missing_token_type() {
    // HOTP wird an der Importgrenze uebersprungen (B-1, s. Aegis-Pendant
    // oben); der Eintrag ohne tokenType bleibt TOTP (Default) und kommt an.
    let raw = format!(
        r#"{{"services":[
            {{"name":"H","secret":"{SECRET}","otp":{{"tokenType":"HOTP","counter":7}}}},
            {{"name":"Legacy","secret":"{SECRET}","otp":{{}}}}]}}"#
    );
    let (accs, skipped) = parse_json_backup(&raw).unwrap();
    assert_eq!(accs.len(), 1);
    assert_eq!(accs[0].kind, OtpKind::Totp); // fehlender tokenType → TOTP
    assert_eq!(accs[0].issuer, "Legacy");
    // B-55: der Skip-Grund fuer den HOTP-Eintrag muss die UI erreichen.
    assert_eq!(skipped.len(), 1);
    assert!(skipped[0].contains("nicht unterstützt"), "{skipped:?}");
}

#[test]
fn twofas_skips_steam() {
    let raw = format!(
        r#"{{"services":[
            {{"name":"Steam","secret":"{SECRET}","otp":{{"tokenType":"STEAM","digits":5}}}},
            {{"name":"Keep","secret":"{SECRET}","otp":{{"tokenType":"TOTP"}}}}]}}"#
    );
    let (accs, skipped) = parse_json_backup(&raw).unwrap();
    assert_eq!(accs.len(), 1);
    assert_eq!(accs[0].issuer, "Keep");
    assert_eq!(skipped.len(), 1);
    assert!(skipped[0].contains("nicht unterstützt"), "{skipped:?}");
}

#[test]
fn twofas_skips_unsupported_algorithms_but_keeps_totp() {
    // B-56: SHA224/SHA384/MD5 werden zu Recht verworfen (nicht
    // implementiert), aber der Grund muss die UI erreichen statt nur im
    // Log zu landen - Kette bereits durch B-55 (Rang 6) hergestellt.
    let raw = format!(
        r#"{{"services":[
            {{"name":"S224","secret":"{SECRET}","otp":{{"algorithm":"SHA224"}}}},
            {{"name":"S384","secret":"{SECRET}","otp":{{"algorithm":"SHA384"}}}},
            {{"name":"M","secret":"{SECRET}","otp":{{"algorithm":"MD5"}}}},
            {{"name":"Keep","secret":"{SECRET}","otp":{{"algorithm":"SHA256"}}}}]}}"#
    );
    let (accs, skipped) = parse_json_backup(&raw).unwrap();
    assert_eq!(accs.len(), 1);
    assert_eq!(accs[0].issuer, "Keep");
    assert_eq!(skipped.len(), 3);
    assert!(skipped.iter().all(|s| s.contains("nicht unterstützt")), "{skipped:?}");
}

#[test]
fn twofas_rejects_newer_than_known_schema_version() {
    // B-54: gleiche Begruendung wie bei Aegis.
    let raw = r#"{"schemaVersion":99,"services":[]}"#;
    let err = parse_json_backup(raw).unwrap_err().to_string();
    assert!(err.contains("Unbekanntes 2FAS-Export-Format"), "{err}");
}

#[test]
fn twofas_encrypted_is_rejected() {
    let raw = r#"{"schemaVersion":4,"servicesEncrypted":"AAAA:BBBB:CCCC","services":[]}"#;
    let err = parse_json_backup(raw).unwrap_err().to_string();
    assert!(err.contains("passwortgeschützt"), "{err}");
}

#[test]
fn twofas_encrypted_without_services_key_is_rejected() {
    let raw = r#"{"schemaVersion":4,"servicesEncrypted":"AAAA:BBBB:CCCC"}"#;
    let err = parse_json_backup(raw).unwrap_err().to_string();
    assert!(err.contains("passwortgeschützt"), "{err}");
}

#[test]
fn twofas_without_usable_entries_errors() {
    let err = parse_json_backup(r#"{"services":[]}"#).unwrap_err().to_string();
    assert!(err.contains("keine importierbaren"), "{err}");
}

// ── Robustheit gegen bösartige Eingaben ──────────────────

#[test]
fn rejects_broken_and_empty_json() {
    for raw in ["", "   ", "{", "null", "[]", "\"string\"", "{\"db\":}"] {
        assert!(parse_json_backup(raw).is_err(), "sollte scheitern: {raw:?}");
    }
}

#[test]
fn rejects_unknown_schema() {
    let err = parse_json_backup(r#"{"accounts":[{"secret":"x"}]}"#)
        .unwrap_err()
        .to_string();
    assert!(err.contains("weder als Aegis"), "{err}");
}

#[test]
fn deeply_nested_json_errors_without_stack_overflow() {
    // serde_json bricht bei ~128 Ebenen mit Fehler ab statt zu rekursieren.
    let raw = "[".repeat(100_000);
    assert!(parse_json_backup(&raw).is_err());
    let nested = format!(r#"{{"db":{}}}"#, "[".repeat(50_000));
    assert!(parse_json_backup(&nested).is_err());
}

#[test]
fn numeric_extremes_do_not_panic() {
    // i64-Grenzen und Overflow-Kandidaten: Eintrag wird verworfen bzw. die
    // Datei sauber abgelehnt — in keinem Fall ein Panic.
    let extras = [
        r#""digits":9223372036854775807"#,
        r#""period":9223372036854775807"#,
        r#""period":4294967296"#,
        r#""counter":-9223372036854775808"#,
        r#""counter":9223372036854775807"#,
        r#""digits":1e309"#,
        r#""digits":6.5"#,
        r#""digits":"6""#,
    ];
    for extra in extras {
        let raw = aegis(&format!(
            r#"{{"type":"totp","name":"n","issuer":"I",
                 "info":{{"secret":"{SECRET}",{extra}}}}}"#
        ));
        // Kein unwrap: manche Fälle sind Err (Typfehler), manche Ok mit
        // verworfenem Eintrag. Wichtig ist nur: sauberer Abschluss statt Panic.
        let _ = parse_json_backup(&raw);
    }
}

#[test]
fn very_long_strings_are_handled() {
    let long = "A".repeat(200_000);
    let raw = aegis(&format!(
        r#"{{"type":"{long}","name":"{long}","issuer":"{long}","info":{{"secret":"{long}"}}}}"#
    ));
    // Unbekannter Typ → übersprungen → keine importierbaren Einträge.
    assert!(parse_json_backup(&raw).is_err());
}

#[test]
fn long_names_are_capped_not_stored_in_full() {
    let long = "N".repeat(50_000);
    let raw = aegis(&format!(
        r#"{{"type":"totp","name":"{long}","issuer":"{long}","info":{{"secret":"{SECRET}"}}}}"#
    ));
    let (accs, _skipped) = parse_json_backup(&raw).unwrap();
    assert_eq!(accs[0].issuer.chars().count(), MAX_NAME_CHARS);
    assert_eq!(accs[0].label.chars().count(), MAX_NAME_CHARS);
}

#[test]
fn too_many_entries_are_refused() {
    let entry = format!(r#"{{"type":"totp","name":"n","issuer":"i","info":{{"secret":"{SECRET}"}}}}"#);
    let many = vec![entry; MAX_ENTRIES + 1].join(",");
    let err = parse_json_backup(&aegis(&many)).unwrap_err().to_string();
    assert!(err.contains("mehr als"), "{err}");

    let svc = format!(r#"{{"name":"n","secret":"{SECRET}","otp":{{}}}}"#);
    let raw = format!(r#"{{"services":[{}]}}"#, vec![svc; MAX_ENTRIES + 1].join(","));
    assert!(parse_json_backup(&raw).unwrap_err().to_string().contains("mehr als"));
}

#[test]
fn type_error_message_never_echoes_file_content() {
    // Ein Secret an einer Stelle, wo serde einen anderen Typ erwartet:
    // die serde-Meldung würde den Wert enthalten – unsere darf das nicht,
    // denn error.rs reicht Display-Texte 1:1 ans Frontend.
    let raw = format!(r#"{{"db":{{"entries":"{SECRET}"}}}}"#);
    let err = parse_json_backup(&raw).unwrap_err().to_string();
    assert!(!err.contains(SECRET), "Fehlertext leakt Dateiinhalt: {err}");

    let raw = format!(r#"{{"services":"{SECRET}"}}"#);
    let err = parse_json_backup(&raw).unwrap_err().to_string();
    assert!(!err.contains(SECRET), "Fehlertext leakt Dateiinhalt: {err}");

    let raw = aegis(&format!(
        r#"{{"type":"totp","name":"n","issuer":"i","info":{{"secret":"{SECRET}","digits":"{SECRET}"}}}}"#
    ));
    let err = parse_json_backup(&raw).unwrap_err().to_string();
    assert!(!err.contains(SECRET), "Fehlertext leakt Dateiinhalt: {err}");
}

#[test]
fn utf8_bom_is_tolerated() {
    let raw = format!(
        "\u{feff}{}",
        aegis(&format!(
            r#"{{"type":"totp","name":"n","issuer":"I","info":{{"secret":"{SECRET}"}}}}"#
        ))
    );
    assert_eq!(parse_json_backup(&raw).unwrap().0.len(), 1);
}

#[test]
fn secret_with_padding_and_spaces_is_normalised() {
    let raw = aegis(r#"{"type":"totp","name":"n","issuer":"I",
        "info":{"secret":"jbsw y3dp ehpk 3pxp="}}"#);
    let (accs, _skipped) = parse_json_backup(raw.as_str()).unwrap();
    assert_eq!(accs[0].secret_b32.as_str(), SECRET);
}
