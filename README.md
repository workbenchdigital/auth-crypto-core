# auth-crypto-core

Der plattformneutrale Kern von **AUth**, einem TOTP-Authenticator für Windows:
Schlüsselableitung, authentifizierte Verschlüsselung, das Vault- und
Backup-Dateiformat, die TOTP-Berechnung und die Parser für Fremdformate.

Kein Dateisystem, keine OS-Bindung, kein Netzwerk. Das liegt alles in der
Anwendung, die nicht Teil dieses Repositories ist.

> **Note for non-German readers:** the code comments in this repository are in
> German, and there are a lot of them — they carry most of the reasoning behind
> the security decisions. An English translation does not exist yet.

## Warum das hier öffentlich liegt

AUth wird mit dem Versprechen verkauft, dass die Konten dem Nutzer gehören und
auch dann nutzbar bleiben, wenn es den Hersteller nicht mehr gibt. Ein solches
Versprechen ist wenig wert, solange niemand nachsehen kann, wie die
Verschlüsselung tatsächlich funktioniert.

Deshalb liegt der Teil offen, auf den es dabei ankommt. Nicht als
Marketing-Geste: Wer hier einen Fehler findet, findet einen echten — siehe
[SECURITY.md](SECURITY.md).

## Was hier drin ist

| Modul | Inhalt |
|---|---|
| `crypto/kdf` | Argon2id, Unicode-NFC-Normalisierung des Passworts |
| `crypto/aead` | XChaCha20-Poly1305 mit domänentrennender AAD |
| `vault` | Vault-Dateiformat: KEK umschließt MasterKey, MasterKey verschlüsselt den Body |
| `backup` | `.agbak`-Format mit eigenem Passwort |
| `migration` | Schema-Migration älterer Vault-Stände |
| `model` | Datenmodell und Validierung |
| `totp` | TOTP-Berechnung (RFC 6238) |
| `importers` | Parser für `otpauth://`, Google-Authenticator-Migration, Aegis- und 2FAS-JSON |

Bewusst **nicht** hier: die Lizenzprüfung der App. Sie ist keine
Vertraulichkeitsgrenze, und nichts in diesem Crate hängt von ihr ab.

## Bauen und prüfen

```bash
cargo test
```

107 Tests, keine Netzwerkzugriffe, keine Testfixtures außerhalb des Repos.
Mindestens Rust 1.80.

Darunter sind die Tests, die tatsächlich etwas beweisen und nicht nur
Roundtrips fahren:

- **Golden-Fixtures** für Vault und Backup — echte, eingefrorene Ciphertexte
  aus einer früheren Codeversion. Sie fallen, wenn eine Änderung das
  Dateiformat bricht, und zwar auch dann, wenn sie es *konsistent* in beide
  Richtungen bricht. Genau das übersehen Roundtrip-Tests: Wer AAD-Strings,
  Base64-Alphabet oder Feldnamen einheitlich ändert, bleibt bei ihnen grün und
  macht trotzdem jede existierende Datei unlesbar.
- **RFC-6238-Testvektoren** für die TOTP-Berechnung.
- **Normalisierungs-Tests** (NFC/NFD): dasselbe Passwort, je nach Tastatur oder
  Passwortmanager unterschiedlich kodiert, muss denselben Vault öffnen — und
  Bestandsdateien von vor dieser Korrektur müssen weiter aufgehen.

## Das Verhältnis zum privaten App-Repository

Dieses Repository ist eine **wortgleiche** Kopie des `auth-core`-Crates aus dem
privaten AUth-Repository: dieselbe `Cargo.toml`, dasselbe `src/`. Es gibt
keinen Generierungsschritt, kein umgeschriebenes Manifest und keine für die
Veröffentlichung bereinigten Kommentare.

Wortgleich sind genau diese beiden. Hinzu kommen vier Dateien, die es privat
nicht gibt und die nichts am Code ändern: `README.md`, `SECURITY.md`, `LICENSE`
und `Cargo.lock` — letztere, damit nachvollziehbar ist, gegen welche
Abhängigkeitsversionen die Tests hier gelaufen sind (das private Repository
führt stattdessen ein Workspace-Lockfile über die ganze Anwendung).

Das ist eine bewusste Entscheidung gegen die bequemere Variante. Sobald ein
Skript zwischen privatem und öffentlichem Stand steht, wird aus „das ist der
ausgelieferte Code" ein Versprechen — und ein Skript kann still ein falsches
Artefakt erzeugen.

**Was das ehrlicherweise nicht leistet:** Ohne Zugang zum privaten Repository
lässt sich von außen nicht unabhängig überprüfen, dass beide Stände
übereinstimmen, und ohne reproduzierbare Builds nicht, dass die ausgelieferte
`.exe` genau diesen Code enthält. Reproduzierbare Builds gibt es hier noch
nicht. Was die Wortgleichheit leistet, ist die Beseitigung des
*Divergenz-Mechanismus*: Es existiert keine Stelle, an der die beiden Stände
planmäßig auseinanderlaufen könnten.

Jeder Sync-Commit nennt den Commit-Hash des privaten Repositories, aus dem er
stammt.

### Zwei Eigenheiten, die aus dieser Entscheidung folgen

**`B-nn` in Kommentaren** (etwa `B-104`, `B-165`) verweisen auf Befunde aus dem
internen Audit-Protokoll der App. Das Protokoll selbst ist nicht öffentlich —
die Nummern bleiben trotzdem stehen, weil sie zu entfernen die Wortgleichheit
zerstören würde. Die Kommentare erklären den jeweiligen Sachverhalt vollständig
aus sich heraus; die Nummer ist nur die Fundstelle.

**Verweise auf `src-tauri/…`** zeigen auf Dateien der Anwendung, die es hier
nicht gibt. Sie beschreiben, wo die App an diesen Kern andockt — etwa wie sie
`CoreError` auf ihre eigenen Fehlercodes abbildet.

## Versionierung

`0.x`, und das ist kein Platzhalter. Dieses Crate ist zum **Nachprüfen**
veröffentlicht, nicht als Bibliothek mit Stabilitätszusage. Die API kann sich
ändern, wenn die Anwendung es erfordert. Wer darauf aufbaut, sollte eine exakte
Version pinnen.

Die Versionsnummer ist absichtlich von der App-Version entkoppelt.

## Lizenz

MIT — siehe [LICENSE](LICENSE).
