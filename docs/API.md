# GUN-101-GKP API Reference

This document is the authoritative reference for the **external interface** of the
GUN-101-GKP (Ghost Key Protocol) library: its public Python API and its command-line
interface. It describes both the inputs and outputs of every public operation.

- **Protocol name:** `GUN-101-GKP`
- **Current format version:** `2.1`
- **Runtime dependency:** `cryptography >= 42.0.0`
- **Python requirement:** `>= 3.10`

---

## 1. Command-line interface (`gun101gkp`)

Installing the package provides the `gun101gkp` executable. Every subcommand
follows the form `gun101gkp <command> [options]`.

### `gun101gkp generate-identity [--passphrase]`

Generates a new RSA-4096 key pair and stores the private key on disk.

- **Input:** optional `--passphrase` flag. When set, prompts (twice) for a
  passphrase to encrypt the private key.
- **Output (stdout):** the Identity Token (starts with `GUN101GKP-v2-`) and the
  public-key fingerprint.
- **Output (side effect):** writes `~/.gun101gkp/private_key.pem` with mode `0600`.
- **Error:** prints to stderr and exits non-zero if an identity already exists.

### `gun101gkp show-identity`

Displays the stored Identity Token.

- **Output (stdout):** the token for the stored identity.
- **Error:** stderr + non-zero exit if no identity exists.

### `gun101gkp fingerprint [--token <TOKEN>]`

Shows the SHA-256 fingerprint of an identity token (colon-separated uppercase hex
pairs), or of the stored identity if `--token` is omitted.

- **Input:** optional `--token`.
- **Output (stdout):** the fingerprint.

### `gun101gkp encrypt <FILE> --recipient <TOKEN> [--output <PATH>]`

Encrypts a file for a recipient using their Identity Token. No password needed.

- **Input:** the file path, the recipient token, optional output path.
- **Output:** a `.gkp` container file (default `<FILE>.gkp`).

### `gun101gkp decrypt <FILE> [--passphrase] [--output <PATH>]`

Decrypts a container as the stored recipient.

- **Input:** the container path, optional `--passphrase` flag and output path.
- **Output (side effect):** writes the decrypted file (default: input with `.gkp`
  removed).

### `gun101gkp reset-identity`

Irreversibly deletes the stored identity after confirming by typing `YES`.

### `gun101gkp --version`

Prints the installed package version.

---

## 2. Python API

The public API is exported from the top-level `gun101gkp` package.

### Identity management (`gun101gkp.identity`)

#### `generate_identity(passphrase: Optional[str] = None) -> str`

Generates and stores an RSA-4096 key pair.

- **Input:** optional `passphrase` to encrypt the private key.
- **Returns:** the Identity Token (string).
- **Raises:** `ValueError` if an identity already exists.

#### `get_identity_token() -> str`

- **Returns:** the stored Identity Token.
- **Raises:** `ValueError` if no identity exists.

#### `get_identity_fingerprint(token: Optional[str] = None) -> str`

- **Input:** optional identity token; defaults to the stored identity.
- **Returns:** the SHA-256 public-key fingerprint as colon-separated uppercase hex.

#### `has_identity() -> bool`

- **Returns:** `True` if a private key file exists.

#### `reset_identity() -> None`

Deletes the stored private key. **Irreversible.**

- **Raises:** `ValueError` if no identity exists.

#### `load_private_key(passphrase: Optional[str] = None) -> RSAPrivateKey`

Loads and validates the stored private key.

- **Raises:** `FileNotFoundError` if the key file is missing; `ValueError` on a
  wrong passphrase or an invalid key (wrong size or non-whitelisted exponent).

#### `load_public_key_from_token(token: str) -> RSAPublicKey`

Parses an Identity Token into an `RSAPublicKey`.

- **Raises:** `ValueError` if the token has the wrong prefix, malformed base64, or
  is not a valid DER public key.

### Cipher primitives (`gun101gkp.cipher`)

#### `encrypt(plaintext, key, associated_data=None) -> tuple[bytes, bytes, bytes]`

AES-256-GCM encryption.

- **Input:** `plaintext: bytes`, `key: bytes` (32 bytes), optional
  `associated_data: Optional[bytes]`.
- **Returns:** `(nonce, ciphertext, tag)` where nonce is 12 bytes and tag is 16
  bytes.
- **Raises:** `ValueError` if `key`, `nonce`, or `tag` have the wrong length.

#### `decrypt(nonce, ciphertext, tag, key, associated_data=None) -> bytes`

AES-256-GCM decryption.

- **Returns:** the plaintext.
- **Raises:** `ValueError("Decryption failed")` if authentication fails.

### Container handler (`gun101gkp.handler`)

#### `encrypt_for_recipient(file_data: bytes, recipient_token: str) -> bytes`

Encrypts file data for a recipient.

- **Input:** `file_data: bytes`, `recipient_token: str`.
- **Returns:** the encrypted container as UTF-8 JSON bytes.
- **Raises:** `ValueError` on invalid input or token.

#### `decrypt_as_recipient(container_data: bytes, passphrase: Optional[str] = None) -> bytes`

Decrypts a container with the stored private key.

- **Returns:** the decrypted file data.
- **Raises:** `FileNotFoundError` if no key exists; `ValueError` on invalid
  container or failed decryption.

---

## 3. Container file format

The encrypted container is a JSON object (UTF-8) with base64-encoded fields:

```json
{
  "protocol": "GUN-101-GKP",
  "version": "2.1",
  "recipient_fingerprint": "3A:5F:8C:...:1F:4B",
  "sealed_dek": "<base64 RSA-OAEP encrypted DEK>",
  "nonce": "<base64 12-byte nonce>",
  "ciphertext": "<base64 encrypted payload>",
  "tag": "<base64 16-byte auth tag>"
}
```

- Format `2.0` (encrypted without associated data) and `2.1` (with associated
  data) are both accepted on decryption.
- Fields must remain base64-encoded; all decryption/validation failures raise the
  generic `ValueError("Decryption failed")` to avoid an error-message oracle.

---

## 4. Error contract

- All validation and decryption failures raise `ValueError("Decryption failed")`.
- Only malformed JSON / invalid UTF-8 raises `ValueError("Invalid container format")`.
- Missing private key raises `FileNotFoundError("No private key found")`.
