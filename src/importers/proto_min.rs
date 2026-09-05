//! Minimaler Protobuf-Wire-Format-Decoder.
//!
//! Wir parsen nur das, was wir aus Google-Authenticator-Migrations-Payloads
//! brauchen – kein voller proto3-Compiler nötig. So sparen wir die Build-Zeit-
//! Abhängigkeit `protoc` ein.
//!
//! Wire-Format-Spec: https://protobuf.dev/programming-guides/encoding/

use crate::error::{CoreError, CoreResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireType {
    Varint = 0,
    Fixed64 = 1,
    LengthDelim = 2,
    Fixed32 = 5,
}

impl WireType {
    fn from_u8(v: u8) -> CoreResult<Self> {
        Ok(match v {
            0 => WireType::Varint,
            1 => WireType::Fixed64,
            2 => WireType::LengthDelim,
            5 => WireType::Fixed32,
            other => {
                return Err(CoreError::GoogleMigration(format!(
                    "Unbekannter WireType {other}"
                )))
            }
        })
    }
}

pub struct Decoder<'a> {
    pub buf: &'a [u8],
}

impl<'a> Decoder<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn read_varint(&mut self) -> CoreResult<u64> {
        let mut shift = 0u32;
        let mut value = 0u64;
        loop {
            if self.buf.is_empty() {
                return Err(CoreError::GoogleMigration("Varint EOF".into()));
            }
            let b = self.buf[0];
            self.buf = &self.buf[1..];
            value |= ((b & 0x7f) as u64) << shift;
            if (b & 0x80) == 0 {
                return Ok(value);
            }
            shift += 7;
            if shift >= 64 {
                return Err(CoreError::GoogleMigration("Varint zu lang".into()));
            }
        }
    }

    pub fn read_tag(&mut self) -> CoreResult<(u32, WireType)> {
        let v = self.read_varint()?;
        let field = (v >> 3) as u32;
        let wt = WireType::from_u8((v & 0x7) as u8)?;
        Ok((field, wt))
    }

    pub fn read_length_delim(&mut self) -> CoreResult<&'a [u8]> {
        let len = self.read_varint()? as usize;
        if self.buf.len() < len {
            return Err(CoreError::GoogleMigration("Length-Delimited EOF".into()));
        }
        let (head, tail) = self.buf.split_at(len);
        self.buf = tail;
        Ok(head)
    }

    pub fn skip(&mut self, wt: WireType) -> CoreResult<()> {
        match wt {
            WireType::Varint => {
                self.read_varint()?;
            }
            WireType::Fixed64 => {
                if self.buf.len() < 8 {
                    return Err(CoreError::GoogleMigration("Fixed64 EOF".into()));
                }
                self.buf = &self.buf[8..];
            }
            WireType::Fixed32 => {
                if self.buf.len() < 4 {
                    return Err(CoreError::GoogleMigration("Fixed32 EOF".into()));
                }
                self.buf = &self.buf[4..];
            }
            WireType::LengthDelim => {
                let _ = self.read_length_delim()?;
            }
        }
        Ok(())
    }
}

/// Eine Migration-Payload-Account-Definition (entspricht `OtpParameters`).
#[derive(Debug, Default, Clone)]
pub struct OtpParam {
    pub secret: Vec<u8>,
    pub name: String,
    pub issuer: String,
    /// 0=Unspecified, 1=SHA1, 2=SHA256, 3=SHA512, 4=MD5
    pub algorithm: u32,
    /// 0=Unspecified, 1=Six, 2=Eight
    pub digits: u32,
    /// 0=Unspecified, 1=HOTP, 2=TOTP
    pub otp_type: u32,
    pub counter: u64,
}

/// Ergebnis von `decode_migration`: die Konten **und** die Batch-Metadaten
/// (B-5) - Google verteilt große Exporte (>10 Konten) über mehrere QR-Codes
/// mit gemeinsamer `batch_id`, unterschiedlichem `batch_index` und
/// `batch_size`. Vorher wurden diese drei Felder stillschweigend verworfen.
#[derive(Debug, Default, Clone)]
pub struct MigrationPayload {
    pub params: Vec<OtpParam>,
    pub batch_size: u32,
    pub batch_index: u32,
    /// Nur als Vergleichsschlüssel genutzt, nie arithmetisch - deshalb `u64`
    /// statt der Signed/Unsigned-Unsicherheit von Googles `int32`-Encoding.
    pub batch_id: u64,
}

pub fn decode_migration(payload: &[u8]) -> CoreResult<MigrationPayload> {
    let mut dec = Decoder::new(payload);
    let mut out = MigrationPayload::default();
    while !dec.is_empty() {
        let (field, wt) = dec.read_tag()?;
        match (field, wt) {
            // otp_parameters (repeated)
            (1, WireType::LengthDelim) => {
                let inner = dec.read_length_delim()?;
                out.params.push(decode_otp_param(inner)?);
            }
            (3, WireType::Varint) => out.batch_size = dec.read_varint()? as u32,
            (4, WireType::Varint) => out.batch_index = dec.read_varint()? as u32,
            (5, WireType::Varint) => out.batch_id = dec.read_varint()?,
            (_, wt) => dec.skip(wt)?,
        }
    }
    Ok(out)
}

fn decode_otp_param(buf: &[u8]) -> CoreResult<OtpParam> {
    let mut dec = Decoder::new(buf);
    let mut p = OtpParam::default();
    while !dec.is_empty() {
        let (field, wt) = dec.read_tag()?;
        match (field, wt) {
            (1, WireType::LengthDelim) => p.secret = dec.read_length_delim()?.to_vec(),
            (2, WireType::LengthDelim) => {
                p.name = String::from_utf8_lossy(dec.read_length_delim()?).into_owned();
                // L-5: siehe otpauth.rs - stumme U+FFFD-Ersetzung waere hier
                // besonders unschoen, da name/issuer direkt als Label/Issuer
                // des Kontos landen.
                if p.name.contains('\u{FFFD}') {
                    tracing::warn!("Google-Migration: Konto-Name enthielt ungültige UTF-8-Bytes, wurde ersetzt");
                }
            }
            (3, WireType::LengthDelim) => {
                p.issuer = String::from_utf8_lossy(dec.read_length_delim()?).into_owned();
                if p.issuer.contains('\u{FFFD}') {
                    tracing::warn!("Google-Migration: Issuer enthielt ungültige UTF-8-Bytes, wurde ersetzt");
                }
            }
            (4, WireType::Varint) => p.algorithm = dec.read_varint()? as u32,
            (5, WireType::Varint) => p.digits = dec.read_varint()? as u32,
            (6, WireType::Varint) => p.otp_type = dec.read_varint()? as u32,
            (7, WireType::Varint) => p.counter = dec.read_varint()?,
            (_, wt) => dec.skip(wt)?,
        }
    }
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hilfsfunktion: ein Varint kodieren.
    fn varint(mut v: u64, out: &mut Vec<u8>) {
        while v >= 0x80 {
            out.push((v as u8) | 0x80);
            v >>= 7;
        }
        out.push(v as u8);
    }

    fn tag(field: u32, wt: u8, out: &mut Vec<u8>) {
        let t = ((field as u64) << 3) | (wt as u64);
        varint(t, out);
    }

    fn ld(field: u32, data: &[u8], out: &mut Vec<u8>) {
        tag(field, 2, out);
        varint(data.len() as u64, out);
        out.extend_from_slice(data);
    }

    fn vint(field: u32, v: u64, out: &mut Vec<u8>) {
        tag(field, 0, out);
        varint(v, out);
    }

    #[test]
    fn parses_synthetic_migration_payload() {
        // ein OtpParameters mit secret + name + issuer + algorithm=SHA1 + digits=Six + type=TOTP
        let mut inner = Vec::new();
        ld(1, &[0xDE, 0xAD, 0xBE, 0xEF], &mut inner);
        ld(2, b"alice@example.com", &mut inner);
        ld(3, b"GitHub", &mut inner);
        vint(4, 1, &mut inner); // SHA1
        vint(5, 1, &mut inner); // Six
        vint(6, 2, &mut inner); // TOTP

        let mut outer = Vec::new();
        ld(1, &inner, &mut outer);
        vint(2, 1, &mut outer); // version=1
        vint(3, 1, &mut outer); // batch_size=1
        vint(4, 0, &mut outer); // batch_index=0
        vint(5, 42, &mut outer); // batch_id=42

        let parsed = decode_migration(&outer).unwrap();
        assert_eq!(parsed.params.len(), 1);
        let p = &parsed.params[0];
        assert_eq!(p.secret, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(p.name, "alice@example.com");
        assert_eq!(p.issuer, "GitHub");
        assert_eq!(p.algorithm, 1);
        assert_eq!(p.digits, 1);
        assert_eq!(p.otp_type, 2);
        // B-5: die Batch-Felder waren im Fixture schon immer kodiert, wurden
        // aber nie geprueft - jetzt Teil der eigentlichen Assertion.
        assert_eq!(parsed.batch_size, 1);
        assert_eq!(parsed.batch_index, 0);
        assert_eq!(parsed.batch_id, 42);
    }
}
