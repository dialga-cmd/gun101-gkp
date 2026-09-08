# Security Properties of GUN-101-GKP

GUN-101-GKP (Ghost Key Protocol) is a passwordless asymmetric encryption protocol designed for file encryption. This document outlines the security properties it provides and those it does not claim.

## Cryptographic Primitives

- **RSA-4096**: Used for key encapsulation (encrypting the data encryption key).
- **OAEP padding with SHA-256**: Applied to RSA encryption to prevent chosen-ciphertext attacks.
- **AES-256-GCM**: Used for data encryption, providing confidentiality and authenticity.
- **Random Data Encryption Key (DEK)**: A fresh 256-bit key is generated for each encryption using a cryptographically secure random number generator.

## Security Properties Provided

### 1. Recipient Confidentiality
A file encrypted for recipient A cannot be decrypted by recipient B (who possesses a different RSA private key). This is provided by:
- RSA-OAEP: Ensures that the encrypted DEK can only be decrypted by the holder of the corresponding private key.
- AES-256-GCM: Provides confidentiality of the data under the DEK.

### 2. Resistance to Passive Attacks
A passive attacker who intercepts the encrypted container (containing the ciphertext, nonce, tag, and encrypted DEK) cannot recover the plaintext without the recipient's private key. This relies on:
- The computational hardness of RSA-4096 (factoring).
- The security of AES-256-GCM as a symmetric encryption scheme.

### 3. Integrity and Authenticity
Any tampering with the encrypted container is detected and rejected before any plaintext is returned. This is provided by:
- AES-256-GCM authentication tag: Any modification of the ciphertext or nonce will cause decryption to fail.
- Fingerprint verification: Before attempting to decrypt the DEK, the recipient's public key fingerprint is compared to the one stored in the container (see below).

### 4. Fingerprint Verification
To prevent decryption attempts with the wrong key, the recipient's public key fingerprint is included in the container and verified before any RSA operation. This ensures that:
- An attacker cannot trick the recipient into decrypting a message intended for another party.
- Implementation errors that might leak information via timing side-channels on incorrect keys are avoided.

### 5. Sender Statelessness
The sender needs only the recipient's public key token (a base64-encoded public key with a prefix) and holds no secret material. The sender generates a fresh DEK for each message.

### 6. Memory Safety
The DEK is zeroed out immediately after use in both encryption and decryption functions to prevent leakage from memory dumps.

## Security Properties Not Claimed

### 1. Private Key Compromise
GUN-101-GKP does not protect against compromise of the recipient's private key. If an attacker gains access to the private key, they can decrypt all past and future messages encrypted for that key.

### 2. Malware on Recipient's Machine
The protocol does not protect against malware that steals the plaintext after decryption or the private key before use.

### 3. Quantum Resistance
RSA-4096 is not resistant to quantum attacks via Shor's algorithm. A sufficiently large quantum computer could break the RSA keys.

### 4. Forward Secrecy
If the recipient's private key is compromised at any time, all previously encrypted files can be decrypted. The protocol does not provide forward secrecy.

### 5. Metadata Protection
The protocol does not conceal the length of the plaintext (due to AES-GCM) or the fact that a communication occurred. The container structure is visible.

## Rationale for Design Choices

### Why RSA-4096?
RSA-2048 is considered secure against classical computers for the near future, but RSA-4096 provides a higher security margin and protects against advances in factoring algorithms. The performance impact is acceptable for file encryption where operations are infrequent.

### Why RSA-OAEP with SHA-256?
PKCS#1 v1.5 padding is vulnerable to chosen-ciphertext attacks (e.g., Bleichenbacher attack). OAEP provides provable security against such attacks when used with a secure hash function like SHA-256.

### Why a Random DEK per Encryption?
Deriving the AES key directly from the RSA key would require deterministic encryption, which is insecure. Using a random DEK per message ensures that encrypting the same plaintext multiple times produces different ciphertexts (semantic security). It also limits the amount of data encrypted with a single key to a manageable size.

### Why Fingerprint Verification Before RSA Operation?
Performing RSA decryption is expensive. By verifying the fingerprint first, we avoid unnecessary computation if the key is incorrect. This also prevents potential side-channel leaks from the RSA decryption operation when given a ciphertext not intended for the recipient.

### Why AES-256-GCM?
AES-GCM provides authenticated encryption with associated data (AEAD) in a single primitive, ensuring both confidentiality and integrity. The 128-bit authentication tag provides a negligible probability of forgery.

## Honest Assessment

GUN-101-GKP is designed for authenticating the recipient and providing confidentiality against passive attackers. It is suitable for scenarios where a publisher wants to distribute files that only a specific holder of a private key can read, without needing to share a password or perform an interactive key exchange.

Users must protect their private key diligently. Loss of the private key means permanent loss of access to all files encrypted with the corresponding public key.

The protocol does not claim to be secure against advanced threats such as nation-state attackers with quantum capabilities or compromised endpoints. It is a practical solution for everyday confidentiality needs based on well-vetted cryptographic primitives.

## Error Messages

To prevent Side-Channel attacks via error-message oracles, all validation and decryption errors raise a generic `ValueError` with the message `"Decryption failed"`. The only exception is malformed JSON or invalid UTF-8 in the container, which raises `ValueError` with the message `"Invalid container format"`. This ensures that an attacker cannot distinguish between different failure reasons (e.g., wrong key, tampered ciphertext, or incorrect protocol version) based on the error message alone.

## Release signing keys

Releases are **cryptographically signed** and verifiable (see `RELEASING.md`).
The public signing key belongs to the maintainer, **Aditya Raj**.

- **Key fingerprint:** `(maintainer's GPG key fingerprint — published here once a key is registered)`
- **How to obtain it:**
  - In the repository as a signed commit/tag (Verified badge via GitHub).
  - From the maintainer's GitHub profile (**Settings → SSH and GPG keys**).
  - On public key servers (keys.openpgp.org) under the email
    `adityaraj1234@duck.com`.
- **How to verify:** `git tag -v <version>` and `gh attestation verify <artifact>`
  (see [RELEASING.md](RELEASING.md) → "Verifying a signed release").
- **Private key:** the private signing key is **never** stored on PyPI (the
  distribution site); it is held by the maintainer and used to sign git tags
  cryptographically.

## Algorithm agility

GUN-101-GKP deliberately uses a **single, well-audited cryptographic suite**
(RSA-4096/OAEP-SHA256 for key encapsulation and AES-256-GCM for data
encryption) rather than exposing many selectable algorithms. This reduces
misconfiguration risk and the audit surface (a documented secure-design choice;
see `docs/SECURITY.md`). However, algorithm agility is treated as an
**architectural property**: every algorithm and parameter is centralized and
selectable from a single configuration point:

- The symmetric primitives are isolated in `src/gun101gkp/cipher.py` behind the
  `cryptography` library, so AES-256-GCM can be swapped for another AEAD without
  changing the rest of the library.
- RSA parameters (key size, exponent, OAEP hash) are constants in
  `src/gun101gkp/config.py`.
- Because the container format is versioned, a future migration to a different
  algorithm can be introduced as a new format version while continuing to decrypt
  existing containers.

This makes switching a broken algorithm a small, isolated, testable change rather
than a rewrite, satisfying the intent of algorithm agility while keeping a small,
auditable default surface.