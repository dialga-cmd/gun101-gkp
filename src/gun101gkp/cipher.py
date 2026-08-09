import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import AES_NONCE_LEN, DEK_LEN

def encrypt(plaintext: bytes, key: bytes, associated_data: bytes = None) -> tuple[bytes, bytes, bytes]:
    """Encrypt plaintext with AES-256-GCM.

    Args:
        plaintext: The data to encrypt.
        key: The 32-byte DEK.
        associated_data: Optional associated data for authentication.

    Returns:
        A tuple (nonce, ciphertext, tag) where:
            nonce: 12-byte nonce used for encryption.
            ciphertext: The encrypted bytes (without the tag).
            tag: 16-byte authentication tag.
    """
    if len(key) != DEK_LEN:
        raise ValueError(f"Key must be {DEK_LEN} bytes long")

    nonce = os.urandom(AES_NONCE_LEN)
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data)
    # AESGCM appends the tag to the ciphertext
    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]
    return nonce, ciphertext, tag

def decrypt(nonce: bytes, ciphertext: bytes, tag: bytes, key: bytes, associated_data: bytes = None) -> bytes:
    """Decrypt ciphertext with AES-256-GCM.

    Args:
        nonce: The 12-byte nonce used for encryption.
        ciphertext: The encrypted bytes (without the tag).
        tag: The 16-byte authentication tag.
        key: The 32-byte DEK.
        associated_data: Optional associated data for authentication.

    Returns:
        The decrypted plaintext.

    Raises:
        Exception: If decryption fails (invalid tag).
    """
    if len(key) != DEK_LEN:
        raise ValueError(f"Key must be {DEK_LEN} bytes long")
    if len(nonce) != AES_NONCE_LEN:
        raise ValueError(f"Nonce must be {AES_NONCE_LEN} bytes long")
    if len(tag) != 16:
        raise ValueError("Tag must be 16 bytes long")

    ciphertext_with_tag = ciphertext + tag
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)
    except Exception as e:
        raise ValueError("Decryption failed") from e
    return plaintext