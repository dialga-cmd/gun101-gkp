import json
import base64
import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

from .config import PROTOCOL, VERSION, DEK_LEN
from .identity import load_private_key, load_public_key_from_token, get_identity_fingerprint
from .cipher import encrypt as aes_encrypt, decrypt as aes_decrypt

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
        raise ValueError(str(e)) from e
    except Exception as e:
        raise ValueError(f"Invalid recipient token: {e}") from e

    # Generate random DEK
    dek = os.urandom(DEK_LEN)

    # Encrypt file data with DEK using AES-256-GCM
    nonce, ciphertext, tag = aes_encrypt(file_data, dek)

    # Seal DEK with RSA-OAEP
    try:
        sealed_dek = public_key.encrypt(
            dek,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        raise ValueError(f"Failed to seal DEK: {e}") from e

    # Compute recipient fingerprint from token
    recipient_fingerprint = get_identity_fingerprint(recipient_token)

    # Wipe DEK from memory
    dek = bytes(DEK_LEN)
    del dek

    # Build container
    container = {
        "protocol": PROTOCOL,
        "version": VERSION,
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
        raise ValueError(f"Invalid container format: {e}") from e

    # Verify protocol and version
    if container.get("protocol") != PROTOCOL:
        raise ValueError(f"Invalid protocol: expected {PROTOCOL}, got {container.get('protocol')}")
    if container.get("version") != VERSION:
        raise ValueError(f"Invalid version: expected {VERSION}, got {container.get('version')}")

    # Load recipient's private key
    try:
        private_key = load_private_key(passphrase)
    except FileNotFoundError:
        raise FileNotFoundError("No private key found")
    except ValueError as e:
        raise ValueError(f"Failed to load private key: {e}") from e

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
        raise ValueError("This file was not encrypted for this identity.")

    # Decode sealed DEK
    try:
        sealed_dek = base64.b64decode(container["sealed_dek"])
    except Exception as e:
        raise ValueError(f"Invalid sealed_dek encoding: {e}") from e

    # Unseal DEK with RSA-OAEP
    try:
        dek = private_key.decrypt(
            sealed_dek,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        raise ValueError(f"Failed to unseal key: {e}") from e

    # Decode nonce, ciphertext, tag
    try:
        nonce = base64.b64decode(container["nonce"])
        ciphertext = base64.b64decode(container["ciphertext"])
        tag = base64.b64decode(container["tag"])
    except Exception as e:
        raise ValueError(f"Invalid base64 in container fields: {e}") from e

    # Decrypt file data with DEK
    try:
        plaintext = aes_decrypt(nonce, ciphertext, tag, dek)
    except ValueError as e:
        # Wipe dek before raising
        dek = bytes(DEK_LEN)
        del dek
        raise ValueError(f"Decryption failed: {e}") from e

    # Wipe DEK from memory
    dek = bytes(DEK_LEN)
    del dek

    return plaintext