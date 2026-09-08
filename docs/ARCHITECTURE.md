# GUN-101-GKP Architecture

This document describes the high-level design of GUN-101-GKP (Ghost Key
Protocol): the module structure, the data flow of encryption and decryption, and
the on-disk container format. It is the companion to the more detailed
[`API.md`](API.md) reference.

## Overview

GUN-101-GKP is a **passwordless asymmetric file-encryption library**. A recipient
generates an RSA-4096 key pair and shares only a public **Identity Token**. A
sender uses that token to encrypt a file; only the recipient can decrypt it. No
password or shared secret is exchanged.

The design combines two well-understood cryptographic mechanisms controlled by a
small, reviewed module set:

- **Key encapsulation** — RSA-4096 with OAEP (MGF1-SHA256 / SHA-256) wraps a
  per-file random data encryption key (DEK).
- **Authenticated data encryption** — AES-256-GCM encrypts the file under the
  DEK, providing confidentiality and integrity.

## Module structure

```
src/gun101gkp/
    config.py    # Protocol/format constants, key sizes, paths (security knobs)
    cipher.py    # AES-256-GCM encrypt/decrypt primitives
    identity.py  # RSA keygen, token/fingerprint, private-key storage
    handler.py   # Container build/parse; orchestration of RSA-OAEP + AES-GCM,
                 #   including binding of associated data (AAD)
    cli.py       # argparse command-line interface
    __init__.py  # Public API re-exports
```

### `config.py` — single source of security configuration
Holds the protocol name, container format version (`2.1`), supported versions
(`2.0`, `2.1`), RSA key size (4096), public exponent (65537), DEK length (32),
nonce length (12), private-key path, and token prefix. Every security-critical
parameter is centralized here so it can be audited in one place.

### `cipher.py` — symmetric primitives
A thin wrapper around the `cryptography` library's `AESGCM`. Returns
`(nonce, ciphertext, tag)` on encrypt and validates lengths on decrypt. Any
authentication failure raises the generic `ValueError("Decryption failed")`.

### `identity.py` — key and identity handling
Generates RSA-4096 key pairs, serializes the private key to PEM (written with
mode `0600`, `O_CREAT | O_EXCL`), parses Identity Tokens back into public keys,
computes SHA-256 fingerprints, and loads/validates the stored private key
(validates size and RSA public exponent whitelist `{3, 65537}`).

### `handler.py` — encryption/decryption orchestration
The core of the protocol. `encrypt_for_recipient` generates a fresh DEK, AES-GCM
encrypts the file with the header fields as **associated data (AAD)**, and RSA-OAEP
seals the DEK. `decrypt_as_recipient` reverses this: verifies the protocol and
version, loads the private key, verifies the recipient fingerprint **before** any
RSA operation, unseals the DEK, and AES-GCM decrypts with AAD.

### `cli.py` — interface
Parses subcommands and wires them to the `identity` and `handler` functions.

## Encryption data flow

```
file_data ──▶ AES-256-GCM ──▶ nonce, ciphertext, tag
                 ▲ AAD = {protocol, version, recipient_fingerprint}
                 │
DEK (os.urandom) ─▶ RSA-OAEP (recipient public key) ──▶ sealed_dek
                 │
                 └── wiped from memory after use (zeroing)

container = base64({protocol, version, recipient_fingerprint,
                    sealed_dek, nonce, ciphertext, tag})
```

## Decryption data flow

```
container ──▶ parse & verify protocol/version
           ──▶ load private key
           ──▶ verify recipient fingerprint == container fingerprint  (before RSA)
           ──▶ RSA-OAEP unseal ──▶ DEK
           ──▶ AES-GCM decrypt (AAD for v2.1) ──▶ plaintext
           ──▶ wipe DEK from memory
```

## Container format

See [`API.md#container-file-format`](API.md) for the full field listing. Key
points: all fields are base64-encoded; format `2.0` (no AAD) and `2.1` (with AAD,
binding the protocol, version, and recipient fingerprint to the ciphertext) are
both accepted for decryption; new encryptions use `2.1`.

## Security design principles

- **Fresh DEK per file** — semantic security and bounded ciphertext per key.
- **AAD binding** — prevents ciphertext from being repurposed across headers.
- **Fingerprint check before RSADecrypt** — avoids expensive/wrong-key operations
  and reduces DoS surface.
- **Generic error messages** — no error-message oracle between failure modes.
- **Memory wiping** — the DEK is zeroed after use in both paths.
- **Delegated crypto** — all primitives come from the audited `cryptography`
  library; no hand-rolled cryptography.

For the precise security properties and threat model, see
[`SECURITY.md`](SECURITY.md) and [`THREAT_MODEL.md`](THREAT_MODEL.md).
