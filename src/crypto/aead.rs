//! XChaCha20-Poly1305 AEAD-Wrapper.
//!
//! - Schlüssel: 32 Byte.
//! - Nonce: 24 Byte (XChaCha → kein Nonce-Reuse-Risiko bei Zufallsnonce).
//! - Tag: 16 Byte (im Ciphertext enthalten via `aead`-API).
//! - AAD wird beim Versiegeln eingebunden und beim Öffnen geprüft.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{CoreError, CoreResult};

pub const AEAD_KEY_LEN: usize = 32;
pub const AEAD_NONCE_LEN: usize = 24;

/// On-Disk-Format eines AEAD-Eintrags.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AeadCiphertext {
    /// Base64 (URL-Safe, no-pad).
    pub nonce: String,
    /// Base64 (URL-Safe, no-pad). Ciphertext + 16-Byte-Tag.
    pub ct: String,
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
        .map_err(|e| CoreError::Crypto(format!("Base64-Decode: {e}")))
}

fn cipher(key: &[u8]) -> CoreResult<XChaCha20Poly1305> {
    if key.len() != AEAD_KEY_LEN {
        return Err(CoreError::Crypto(format!(
            "Key-Länge {} ≠ {}",
            key.len(),
            AEAD_KEY_LEN
        )));
    }
    let arr: [u8; AEAD_KEY_LEN] = key.try_into().expect("checked length");
    Ok(XChaCha20Poly1305::new(&arr.into()))
}

/// Versiegelt `plaintext` mit `key`. Bindet `aad` als zusätzliche Authentifizierung.
pub fn aead_seal(key: &[u8], plaintext: &[u8], aad: &[u8]) -> CoreResult<AeadCiphertext> {
    let cipher = cipher(key)?;
    let mut nonce_bytes = [0u8; AEAD_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| CoreError::Crypto(format!("AEAD-Seal: {e}")))?;
    Ok(AeadCiphertext {
        nonce: encode(&nonce_bytes),
        ct: encode(&ct),
    })
}

/// Öffnet einen Ciphertext und prüft `aad`. Bei Fehlschlag `DecryptFailed`
/// (kein Detail, um kein Orakel über Tag-vs-Padding zu bieten).
///
/// B-104: Rückgabe ist `Zeroizing<Vec<u8>>`, nicht `Vec<u8>` - was hier
/// herauskommt, ist per Definition entschlüsseltes Geheimnis (Vault-Body mit
/// allen TOTP-Secrets im Klartext-JSON, der gewrappte MasterKey, eine
/// .agbak-Payload). Als nacktes `Vec` blieb jede dieser Entschlüsselungen
/// nach dem Drop unüberschrieben im Heap liegen - `derive_key` gibt aus
/// demselben Grund längst `Zeroizing<[u8; KEY_LEN]>` zurück.
pub fn aead_open(
    key: &[u8],
    ciphertext: &AeadCiphertext,
    aad: &[u8],
) -> CoreResult<Zeroizing<Vec<u8>>> {
    let cipher = cipher(key)?;
    let nonce_bytes = decode(&ciphertext.nonce)?;
    if nonce_bytes.len() != AEAD_NONCE_LEN {
        return Err(CoreError::Crypto("Nonce-Länge ungültig".into()));
    }
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ct = decode(&ciphertext.ct)?;
    cipher
        .decrypt(nonce, Payload { msg: &ct, aad })
        .map(Zeroizing::new)
        .map_err(|_| CoreError::DecryptFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; AEAD_KEY_LEN] {
        let mut k = [0u8; AEAD_KEY_LEN];
        OsRng.fill_bytes(&mut k);
        k
    }

    #[test]
    fn roundtrip() {
        let k = key();
        let pt = b"super geheime daten";
        let aad = b"vault-v1";
        let sealed = aead_seal(&k, pt, aad).unwrap();
        let opened = aead_open(&k, &sealed, aad).unwrap();
        assert_eq!(opened.as_slice(), pt);
    }

    #[test]
    fn wrong_aad_fails() {
        let k = key();
        let sealed = aead_seal(&k, b"hello", b"a").unwrap();
        let err = aead_open(&k, &sealed, b"b").unwrap_err();
        assert!(matches!(err, CoreError::DecryptFailed));
    }

    #[test]
    fn tamper_ciphertext_fails() {
        let k = key();
        let mut sealed = aead_seal(&k, b"data", b"aad").unwrap();
        // erste Bytes des Ciphertexts beschädigen
        let mut bytes = decode(&sealed.ct).unwrap();
        bytes[0] ^= 0xFF;
        sealed.ct = encode(&bytes);
        let err = aead_open(&k, &sealed, b"aad").unwrap_err();
        assert!(matches!(err, CoreError::DecryptFailed));
    }

    #[test]
    fn wrong_key_fails() {
        let k1 = key();
        let k2 = key();
        let sealed = aead_seal(&k1, b"x", b"y").unwrap();
        let err = aead_open(&k2, &sealed, b"y").unwrap_err();
        assert!(matches!(err, CoreError::DecryptFailed));
    }
}
