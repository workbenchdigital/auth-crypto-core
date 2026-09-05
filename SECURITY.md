# Security Policy

## Reporting a vulnerability

Please report security issues privately to **support@workbenchdigital.de**.

Do not open a public issue for a suspected vulnerability. Public issues are
fine for everything else.

**What helps:** the affected file and function, what an attacker controls, what
they gain, and a reproducer if you have one. A failing test against this crate
is the most useful form a report can take.

**What to expect:** this crate is maintained by one person, not a team with an
on-call rotation. I aim to acknowledge a report within a week and to tell you
honestly whether and when I can act on it. I will not leave a valid report
unanswered, and I will not dispute a finding I cannot refute.

If you want coordinated disclosure, say so and propose a timeline — I will
work with it. If you publish without contacting me first, that is your call to
make; I would rather read about it late than not at all.

There is no bug bounty. I have no budget for one and would rather say so than
imply otherwise.

## What this crate is

The platform-neutral core of AUth, a Windows TOTP authenticator: key
derivation, authenticated encryption, the vault and backup file formats, TOTP
computation, and parsers for third-party export formats.

It contains no file system access, no OS bindings, and no network code. Those
live in the application, which is not part of this repository.

## Threat model

The properties this crate is meant to hold:

- **Vault confidentiality at rest.** Without the master password, the vault
  body — including every TOTP secret — is not recoverable from the file.
  Argon2id derives a KEK from the password; the KEK wraps a random master key;
  the master key encrypts the body with XChaCha20-Poly1305.
- **Backup confidentiality at rest.** Same construction for `.agbak`, with an
  independent password.
- **Tamper evidence.** AEAD with domain-separating associated data
  (`vault-master-v1`, `vault-body-v1`, `agbak-payload-v1`). A modified
  ciphertext, a swapped envelope field, or a payload lifted from one context
  into another must fail to open rather than decrypt to something plausible.
- **No decryption oracle.** A failure to open returns one uniform error
  regardless of cause — wrong password, corrupted file, wrong magic, wrong
  version.
- **Untrusted input is untrusted.** The importers parse attacker-supplyable
  files (Aegis/2FAS JSON, `otpauth://` URIs, Google Authenticator migration
  payloads). They must not panic, must not echo file content into error
  messages that reach the UI, and must reject rather than guess.
- **Secrets are cleared.** Plaintext secrets are held in `Zeroizing` buffers so
  a dropped vault does not leave them readable in freed heap memory.

A break of any of the above is a vulnerability. Please report it.

## Explicitly out of scope

- **The application around this crate.** File paths, permissions, the tray, the
  updater, Windows Hello integration — none of that is here.
- **License verification.** It is deliberately not part of this repository. It
  is not a confidentiality boundary and nothing in this crate depends on it.
- **Attacks that assume the master password.** An attacker who has the password
  has the vault. That is the design, not a flaw.
- **Attacks that assume code execution as the user.** Memory scraping,
  keylogging, and tampering with the running process are outside what a local
  file format can defend against.

## Known and accepted

Stated here so nobody has to spend time rediscovering them:

- **Argon2 parameters are fixed** (m=64 MiB, t=3, p=4) rather than calibrated
  per machine. They are stored per file, so raising them later stays
  backward-compatible.
- **Opening a backup distinguishes format errors from wrong passwords by
  timing.** Magic, version, and salt length are checked before the KDF runs, so
  a wrong password costs a full Argon2 pass while a malformed file does not.
  This is local-only — there is no network endpoint to time — and the returned
  error is identical in both cases.
- **HOTP is modelled but not implemented.** Counter-based entries are rejected
  at the import boundary rather than stored and silently never working.

## Verifying that this is the shipped code

This repository is a verbatim mirror of the `auth-core` crate inside the
private AUth application repository — same `Cargo.toml`, same `src/`, no
generation step and no rewritten comments. See the README for what that means
and how to check it.
