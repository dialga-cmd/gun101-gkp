import json
import base64
import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

from .config import PROTOCOL, FORMAT_VERSION, SUPPORTED_FORMAT_VERSIONS, DEK_LEN
from .identity import load_private_key, load_public_key_from_token, get_identity_fingerprint
from .cipher import encrypt as aes_encrypt, decrypt as aes_decrypt

AAD_VERSION = "2.1"

def _compute_aad(protocol: str, version: str, recipient_fingerprint: str) -> bytes:
    """Compute associated data for AES-GCM from protocol, version, and recipient fingerprint."""
    # Use compact JSON (no spaces) to ensure consistent encoding
    aad_dict = {
        "protocol": protocol,
        "version": version,
        "recipient_fingerprint": recipient_fingerprint
    }
    return json.dumps(aad_dict, separators=(',', ':')).encode('utf-8')

def _rsa_oaep_padding():
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )

def encrypt_for_recipient(file_data: bytes, recipient_token: str) -> bytes:
    """Encrypt file data for a recipient using their identity token.

    Args:
        file_data: The file contents to encrypt.
        recipient_token: The recipient's identity token (public key with prefix).

    Returns:
        The encrypted container as JSON-encoded UTF-8 bytes.

    Raises:
        ValueError: If inputs are invalid or the token is malformed.
    """
    if not isinstance(file_data, bytes):
        raise ValueError("file_data must be bytes")
    if not isinstance(recipient_token, str):
        raise ValueError("recipient_token must be a string")

    # Load recipient public key
    try:
        public_key = load_public_key_from_token(recipient_token)
    except ValueError as e:
        # Re-raise ValueError from load_public_key_from_token without extra prefix
        raise
    except Exception as e:
        raise ValueError("Invalid recipient token") from e

    # Compute recipient fingerprint
    recipient_fingerprint = get_identity_fingerprint(recipient_token)

    # Generate random DEK
    dek = os.urandom(DEK_LEN)

    # Encrypt file data with DEK using AES-256-GCM
    aad = _compute_aad(PROTOCOL, FORMAT_VERSION, recipient_fingerprint)
    nonce, ciphertext, tag = aes_encrypt(file_data, dek, associated_data=aad)

    # Seal DEK with RSA-OAEP
    try:
        sealed_dek = public_key.encrypt(
            dek,
            _rsa_oaep_padding()
        )
    except Exception as e:
        raise ValueError("Failed to seal DEK") from e

    # Compute recipient fingerprint from token
    recipient_fingerprint = get_identity_fingerprint(recipient_token)

    # Wipe DEK from memory
    dek = bytes(DEK_LEN)
    del dek

    # Build container
    container = {
        "protocol": PROTOCOL,
        "version": FORMAT_VERSION,
        "recipient_fingerprint": recipient_fingerprint,
        "sealed_dek": base64.b64encode(sealed_dek).decode('ascii'),
        "nonce": base64.b64encode(nonce).decode('ascii'),
        "ciphertext": base64.b64encode(ciphertext).decode('ascii'),
        "tag": base64.b64encode(tag).decode('ascii')
    }

    return json.dumps(container).encode('utf-8')

def decrypt_as_recipient(container_data: bytes, passphrase: str = None) -> bytes:
    """Decrypt a container using the recipient's private key.

    Args:
        container_data: The encrypted container as UTF-8 bytes.
        passphrase: Optional passphrase to decrypt the private key.

    Returns:
        The decrypted file data as bytes.

    Raises:
        ValueError: If the container is invalid, malformed, or decryption fails.
        FileNotFoundError: If the private key does not exist.
    """
    if not isinstance(container_data, bytes):
        raise ValueError("container_data must be bytes")

    # Parse JSON container
    try:
        container = json.loads(container_data.decode('utf-8'))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ValueError("Invalid container format") from e

    # Verify protocol and version
    if container.get("protocol") != PROTOCOL:
        raise ValueError("Decryption failed")
    if container.get("version") not in SUPPORTED_FORMAT_VERSIONS:
        raise ValueError("Decryption failed")

    # Load recipient's private key
    try:
        private_key = load_private_key(passphrase)
    except FileNotFoundError:
        raise FileNotFoundError("No private key found")
    except ValueError as e:
        raise ValueError("Failed to load private key") from e

    # Compute fingerprint of loaded public key and compare with container
    public_key = private_key.public_key()
    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    import hashlib
    fingerprint = hashlib.sha256(public_key_der).hexdigest().upper()
    # Format as colon-separated hex pairs
    fingerprint_formatted = ':'.join([fingerprint[i:i+2] for i in range(0, len(fingerprint), 2)])
    container_fingerprint = container.get("recipient_fingerprint")
    if fingerprint_formatted != container_fingerprint:
        # Wipe dek before raising
        dek = bytes(DEK_LEN)
        del dek
        raise ValueError("Decryption failed")

    # Decode sealed DEK
    try:
        sealed_dek = base64.b64decode(container["sealed_dek"])
    except Exception as e:
        raise ValueError("Invalid sealed_dek encoding") from e

    # Unseal DEK with RSA-OAEP
    try:
        dek = private_key.decrypt(
            sealed_dek,
            _rsa_oaep_padding()
        )
    except Exception as e:
        # Wipe dek before raising
        dek = bytes(DEK_LEN)
        del dek
        raise ValueError("Decryption failed") from e

    # Decode nonce, ciphertext, tag
    try:
        nonce = base64.b64decode(container["nonce"])
        ciphertext = base64.b64decode(container["ciphertext"])
        tag = base64.b64decode(container["tag"])
    except Exception as e:
        raise ValueError("Invalid base64 in container fields") from e

    # Determine whether to use associated data based on version
    if container["version"] == "2.0":
        associated_data = None
    else:
        associated_data = _compute_aad(container["protocol"], container["version"], container["recipient_fingerprint"])

    # Decrypt file data with DEK
    try:
        plaintext = aes_decrypt(nonce, ciphertext, tag, dek, associated_data=associated_data)
    except ValueError as e:
        # Wipe dek before raising
        dek = bytes(DEK_LEN)
        del dek
        raise ValueError("Decryption failed") from e

    # Wipe DEK from memory
    dek = bytes(DEK_LEN)
    del dek

    return plaintext