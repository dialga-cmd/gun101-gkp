# Threat Model for GUN-101-GKP

This document outlines the threats considered in the design of GUN-101-GKP and how the protocol addresses them. It also lists threats that are out of scope.

## Assets
- Plaintext file contents
- Recipient's RSA private key
- Recipient's public key token (shared publicly)
- Encrypted container (transmitted or stored)

## Adversaries
We consider a passive network adversary who can eavesdrop on communications and an active adversary who can modify transmitted data. We also consider adversaries with access to the recipient's storage (but not the private key) and adversaries who attempt to trick the recipient into decrypting malicious data.

## Threats Addressed

### 1. Passive Eavesdropping on Encrypted Files
- **Adversary capability**: Intercepts the encrypted container (ciphertext, nonce, tag, encrypted DEK) but does not have the recipient's private key.
- **Mitigation**: The container protects the plaintext via AES-256-GCM encryption with a random DEK, and the DEK is protected by RSA-4096 OAEP encryption. Without the private key, the adversary cannot recover the DEK and thus cannot decrypt the file.

### 2. Active Tampering with Encrypted Container
- **Adversary capability**: Modifies any part of the container (e.g., flips bits in ciphertext, nonce, tag, or sealed DEK).
- **Mitigation**: 
  - Any modification to the ciphertext or nonce will cause the AES-GCM decryption to fail due to authentication tag mismatch.
  - Modification of the tag will cause authentication failure.
  - Modification of the sealed DEK will cause RSA OAEP decryption to fail (or produce an incorrect DEK, leading to authentication failure).
  - The protocol verifies the recipient's public key fingerprint before attempting RSA decryption, preventing decryption attempts with the wrong key.

### 3. Impersonation Attack (Wrong Key Decryption)
- **Adversary capability**: Attempts to trick the recipient into decrypting a container encrypted for a different key.
- **Mitigation**: The container includes the fingerprint of the recipient's public key. Before any RSA operation, the recipient computes the fingerprint of their loaded public key and compares it to the container's value. A mismatch results in an immediate error, preventing the RSA decryption attempt.

### 4. Key Substitution Attack
- **Adversary capability**: Replaces the recipient's public key token with their own to cause the sender to encrypt for the adversary.
- **Mitigation**: This is a threat to the key distribution channel, not the protocol itself. Users must verify the authenticity of public key tokens through an out-of-band channel (e.g., in-person exchange, trusted directory, or certificates). The protocol includes the fingerprint to facilitate such verification.

### 5. Randomness Failure
- **Adversary capability**: Predicts or influences the random number generator used for DEK or nonce generation.
- **Mitigation**: The protocol relies on a cryptographically secure random number generator (os.urandom). If the RNG is compromised, the security is reduced. This is a general limitation of cryptographic systems.

## Threats Out of Scope

### 1. Compromise of Recipient's Private Key
- **Advantage to adversary**: Gains access to the recipient's private key file.
- **Effect**: Can decrypt all past and future containers encrypted for that key.
- **Justification**: Protecting the private key is a key management issue outside the scope of the encryption protocol. Users must secure their private key (e.g., with encryption, hardware tokens, or secure storage).

### 2. Malware on Recipient's Machine
- **Advantage to adversary**: Installs malicious software that steals the plaintext after decryption or captures the private key during use.
- **Effect**: Loss of confidentiality.
- **Justification**: Endpoint security is a separate concern. The protocol assumes a trusted execution environment for decryption.

### 3. Side-Channel Attacks
- **Advantage to adversary**: Uses timing, power consumption, or electromagnetic leaks to deduce the private key.
- **Effect**: Potential private key recovery.
- **Justification**: While the constant-time nature of the cryptographic libraries used helps, side-channel resistance is a deep implementation concern. The protocol relies on the underlying libraries (cryptography.io) to be resistant to common side-channels.

### 4. Quantum Computing Attack
- **Advantage to adversary**: Uses a sufficiently large quantum computer to break RSA-4096 via Shor's algorithm.
- **Effect**: Can decrypt the sealed DEK and thus the file.
- **Justification**: RSA-4096 is not quantum-resistant. If quantum resistance is required, users should consider post-quantum alternatives (not in scope for this protocol).

### 5. Forward Secrecy Compromise
- **Advantage to adversary**: Records encrypted containers and later compromises the private key.
- **Effect**: Can decrypt all previously recorded containers.
- **Justification**: The protocol does not provide forward secrecy because the same long-term private key is used for all key encapsulations. Users who require forward secrecy should use a different protocol (e.g., one based on Diffie-Hellman key exchange).

### 6. Denial of Service
- **Advantage to adversary**: Sends malformed containers to waste the recipient's computational resources.
- **Effect**: Increased CPU usage due to RSA decryption attempts.
- **Mitigation**: The fingerprint check is performed before RSA decryption, reducing the cost of rejecting containers with the wrong key. However, containers with the correct fingerprint but invalid sealed DEK will still trigger an RSA decryption attempt.

## Assumptions
- The recipient's public key token is authentic (verified out-of-band).
- The random number generator used for DEK and nonce generation is cryptographically secure.
- The underlying cryptography library (cryptography.io) is free of vulnerabilities and implements the primitives correctly.
- The execution environment is secure against side-channel and memory scraping attacks during the brief moments when sensitive keys are in memory.

## Recommendations for Users
- Verify recipient public key tokens through an independent channel before first use.
- Protect the private key file with strong access controls and consider encrypting it with a passphrase.
- Regularly backup the private key in a secure location (loss of private key means permanent data loss).
- Stay updated with security patches for dependencies.
- Consider the limitations: no quantum resistance, no forward secrecy, no metadata concealment.