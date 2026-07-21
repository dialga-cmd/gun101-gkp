# GUN-101-GKP: Ghost Key Protocol

A passwordless asymmetric encryption library for file encryption using RSA-4096 and AES-256-GCM.

## What is GUN-101-GKP?

GUN-101-GKP (Ghost Key Protocol) is a Python library that enables secure file encryption without shared secrets or passwords. The recipient generates an RSA-4096 key pair and shares only their public key (called an Identity Token). Anyone with this token can encrypt files for the recipient, but only the holder of the private key can decrypt them.

## Who is it for?

- Individuals who need to send sensitive files to a specific recipient without exchanging passwords or using a secure channel for key agreement.
- Applications that require asymmetric encryption for file storage or transmission where the recipient's identity is known in advance.
- Users who want a simple, stateless encryption scheme where the sender holds no long-term secrets.

## What does it protect?

GUN-101-GKP provides confidentiality of file contents against attackers who do not possess the recipient's private key. Specifically:

- Encrypted files cannot be decrypted without the matching RSA-4096 private key.
- The encrypted container integrates authentication via AES-256-GCM, ensuring that any modification to the ciphertext, nonce, or tag is detected before decryption proceeds.
- A fingerprint of the recipient's public key is included in the container and verified before any RSA operation, preventing decryption attempts with the wrong key.

## What does it NOT protect?

- **Private key compromise**: If the recipient's private key is stolen or leaked, all past and future files encrypted for that key can be decrypted.
- **Malware or endpoint compromise**: The library cannot protect against malware that steals the plaintext before encryption or after decryption, or that steals the private key from the victim's machine.
- **Quantum attacks**: RSA-4096 is vulnerable to Shor's algorithm on a sufficiently large quantum computer. This library does not claim post-quantum security.
- **Forward secrecy**: Compromise of the private key allows decryption of all previously encrypted files; no forward secrecy is provided.
- **Traffic analysis or metadata protection**: The length of the file and the fact that encryption occurred are not concealed.

## How to use it

### 1. Generate an identity (recipient only)

The recipient runs this once to create a key pair:

```bash
gun101gkp generate-identity
```

This prints an Identity Token (starting with `GUN101GKP-v2-`) and a fingerprint. The private key is stored at `~/.gun101gkp/private_key.pem` with permission 600.

Share the Identity Token with anyone who needs to send you encrypted files. You may also share the fingerprint for out-of-band verification.

### 2. Encrypt a file (sender only)

To encrypt a file for a recipient, use their Identity Token:

```bash
gun101gkp encrypt <file> --recipient <TOKEN> [--output <output_path>]
```

Example:
```bash
gun101gkp encrypt report.pdf --recipient GUN101GKP-v2-c2VjcmV0...
```

This creates an encrypted file (default: `report.pdf.gkp`). No password or shared secret is needed.

### 3. Decrypt a file (recipient only)

To decrypt a file received from a sender:

```bash
gun101gkp decrypt <file> [--passphrase] [--output <output_path>]
```

If your private key is encrypted with a passphrase, you will be prompted for it. The decrypted file will be written to the original name without the `.gkp` extension, or to the specified output path.

### 4. Manage your identity

- `gun101gkp show-identity`: Display your stored Identity Token.
- `gun101gkp fingerprint [--token <TOKEN>]`: Show the fingerprint of your stored identity or a provided token.
- `gun101gkp reset-identity`: Delete your private key (irreversible). Warning: This makes all previously encrypted files permanently undecryptable.

## Example workflow

1. **Alice (recipient)** runs:
   ```bash
   $ gun101gkp generate-identity
   Identity token: GUN101GKP-v2-BEkEj...
   Fingerprint: 3A:5F:8C:...:1F:4B
   Warning: Store your private key backup at ~/.gun101gkp/private_key.pem. Losing it makes all encrypted files permanently unreadable.
   ```

2. Alice sends the token (and optionally the fingerprint via a separate channel) to Bob.

3. **Bob (sender)** has a file `contract.pdf` and encrypts it for Alice:
   ```bash
   $ gun101gkp encrypt contract.pdf --recipient GUN101GKP-v2-BEkEj...
   Encrypted file written to: contract.pdf.gkp
   ```

4. Bob sends `contract.pdf.gkp` to Alice (e.g., via email).

5. **Alice** decrypts the file:
   ```bash
   $ gun101gkp decrypt contract.pdf.gkp
   Enter passphrase for private key: ********
   Decrypted file written to: contract.pdf
   ```

## Installation

```bash
pip install gun101-gkp
```

## Algorithm details

- **Key encapsulation**: RSA-4096 with OAEP padding (MGF1-SHA256, label=None).
- **Data encryption**: AES-256-GCM with a random 96-bit nonce.
- **Key derivation**: A fresh 256-bit data encryption key (DEK) is generated per encryption using `os.urandom`.
- **Authentication**: AES-256-GCM provides integrity and authenticity; decryption fails if the ciphertext, nonce, or tag is altered.
- **Key confirmation**: Before any RSA operation, the recipient's public key fingerprint (SHA-256 of the DER-encoded public key, formatted as colon-separated hex) is compared to the value in the container. A mismatch aborts decryption immediately.

## File format

The encrypted container is a JSON object (UTF-8 encoded) base64-encoded fields:

```json
{
  "protocol": "GUN-101-GKP",
  "version": "2.0",
  "recipient_fingerprint": "3A:5F:8C:...:1F:4B",
  "sealed_dek": "<base64-encoded RSA-OAEP encrypted DEK>",
  "nonce": "<base64-encoded 12-byte nonce>",
  "ciphertext": "<base64-encoded encrypted file contents>",
  "tag": "<base64-encoded 16-byte authentication tag>"
}
```

## Security notes

- The private key file (`~/.gun101gkp/private_key.pem`) must be backed up securely. Loss of this file means permanent inability to decrypt any files encrypted for the corresponding public key.
- If you choose to encrypt your private key with a passphrase, remember that loss of the passphrase also results in irreversible loss of the key.
- This library is intended for file encryption. It is not suitable for encrypting large streams or for use in network protocols without additional framing.

## License

MIT License. See the [LICENSE](LICENSE) file for details.