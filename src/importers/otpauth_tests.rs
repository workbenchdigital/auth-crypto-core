use super::*;

#[test]
fn parses_canonical() {
    let uri = "otpauth://totp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30";
    let acc = parse_otpauth_uri(uri).unwrap();
    assert_eq!(acc.issuer, "GitHub");
    assert_eq!(acc.label, "alice@example.com");
    assert_eq!(acc.secret_b32.as_str(), "JBSWY3DPEHPK3PXP");
    assert_eq!(acc.digits, 6);
    assert_eq!(acc.period, 30);
    assert_eq!(acc.algorithm, AlgorithmKind::Sha1);
    assert_eq!(acc.kind, OtpKind::Totp);
}

#[test]
fn parses_label_only_no_issuer_param() {
    let uri = "otpauth://totp/Acme:bob?secret=JBSWY3DPEHPK3PXP";
    let acc = parse_otpauth_uri(uri).unwrap();
    assert_eq!(acc.issuer, "Acme");
    assert_eq!(acc.label, "bob");
}

#[test]
fn parses_url_encoded_label() {
    let uri = "otpauth://totp/Google%20Inc%3Aalice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Google%20Inc";
    let acc = parse_otpauth_uri(uri).unwrap();
    assert_eq!(acc.issuer, "Google Inc");
    assert_eq!(acc.label, "alice@example.com");
}

#[test]
fn rejects_wrong_scheme() {
    assert!(parse_otpauth_uri("https://example.com").is_err());
}

#[test]
fn rejects_missing_secret() {
    assert!(parse_otpauth_uri("otpauth://totp/x?issuer=y").is_err());
}

#[test]
fn rejects_hotp() {
    // HOTP wird von der TOTP-Engine kategorisch abgelehnt (B-1) - ein
    // importiertes HOTP-Konto wuerde nie einen Code liefern, deshalb
    // schon hier an der Importgrenze ablehnen statt speichern.
    assert!(parse_otpauth_uri("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=0").is_err());
}

#[test]
fn parses_sha256_8digits() {
    let uri = "otpauth://totp/Test:foo?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=60";
    let acc = parse_otpauth_uri(uri).unwrap();
    assert_eq!(acc.algorithm, AlgorithmKind::Sha256);
    assert_eq!(acc.digits, 8);
    assert_eq!(acc.period, 60);
}

#[test]
fn accepts_and_normalises_padded_secret() {
    // B-52: Base32-Padding aus Provider-QR-Codes ("...PXP=") wurde bisher
    // nur von add_account akzeptiert, nicht von diesem Parser - die
    // Vorschau zeigte ein Konto, das beim Commit still verschwand.
    let uri = "otpauth://totp/Acme:bob?secret=JBSWY3DPEHPK3PXP=";
    let acc = parse_otpauth_uri(uri).unwrap();
    assert_eq!(acc.secret_b32.as_str(), "JBSWY3DPEHPK3PXP");
}

#[test]
fn rejects_secret_too_short() {
    assert!(parse_otpauth_uri("otpauth://totp/x?secret=AAAA").is_err());
}

#[test]
fn rejects_digits_out_of_range() {
    assert!(parse_otpauth_uri("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=9").is_err());
}
