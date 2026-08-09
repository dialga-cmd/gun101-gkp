import os
import base64
import hashlib
from . import config

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def generate_identity(passphrase: str = None) -> str:
    """Generate a new RSA-4096 keypair and store the private key.

    Args:
        passphrase: Optional passphrase to encrypt the private key.

    Returns:
        The identity token (base64-encoded public key with prefix).

    Raises:
        ValueError: If an identity already exists.
    """
    if has_identity():
        raise ValueError("Identity already exists. Call reset_identity() first.")

    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=config.RSA_PUBLIC_EXPONENT,
        key_size=config.RSA_KEY_SIZE,
    )

    if passphrase is not None:
        encryption_algorithm = serialization.BestAvailableEncryption(passphrase.encode())
    else:
        encryption_algorithm = serialization.NoEncryption()
    # Serialize private key
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm,
    )

    # Ensure directory exists
    os.makedirs(os.path.expanduser(os.path.dirname(config.PRIVATE_KEY_PATH)), exist_ok=True)

    # Write private key with permissions 0o600 atomically
    try:
        fd = os.open(
            os.path.expanduser(config.PRIVATE_KEY_PATH),
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            0o600,
        )
    except FileExistsError:
        # This should not happen because we checked has_identity(), but handle race
        raise ValueError("Identity already exists. Call reset_identity() first.")
    with os.fdopen(fd, 'wb') as f:
        f.write(private_key_pem)
    os.chmod(os.path.expanduser(config.PRIVATE_KEY_PATH), 0o600)

    # Get public key and create token
    public_key = private_key.public_key()
    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    token = config.TOKEN_PREFIX + base64.b64encode(public_key_der).decode('ascii')
    return token

def load_private_key(passphrase: str = None):
    """Load the private key from the stored PEM file.

    Args:
        passphrase: Passphrase to decrypt the private key, if encrypted.

    Returns:
        The loaded private key.

    Raises:
        FileNotFoundError: If the private key file does not exist.
        ValueError: If the passphrase is incorrect or not provided when required.
    """
    private_key_path = os.path.expanduser(config.PRIVATE_KEY_PATH)
    if not os.path.exists(private_key_path):
        raise FileNotFoundError("No private key found")

    with open(private_key_path, 'rb') as f:
        private_key_data = f.read()

    try:
        private_key = serialization.load_pem_private_key(
            private_key_data,
            password=passphrase.encode() if passphrase is not None else None,
        )
    except Exception as e:
        raise ValueError("Failed to load private key") from e
    # Validate loaded private key
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("Loaded key is not an RSA private key")
    if private_key.key_size != config.RSA_KEY_SIZE:
        raise ValueError(f"Invalid key size: expected {config.RSA_KEY_SIZE}, got {private_key.key_size}")
    public_numbers = private_key.public_key().public_numbers()
    # Validate public exponent is sane
    # The library generates keys with exponent 65537 (config.RSA_PUBLIC_EXPONENT), which is
    # the de facto standard for new RSA keys. Exponents 3 and 17 are also accepted as they
    # appear in some legacy RSA implementations and are Fermat primes (F0 and F2).
    # While exponent 3 has theoretical vulnerabilities in textbook RSA, OAEP with SHA-256
    # provides adequate protection against known attacks.
    # Exponents 5 and 257 (other Fermat primes) are rejected as they are extremely rare
    # in practice and offer no significant advantage over 65537.
    if public_numbers.e not in [3, 17, 65537]:
        raise ValueError(f"Unusual public exponent: {public_numbers.e}. Expected 3, 17, or 65537")

    return private_key

def load_public_key_from_token(token: str):
    """Load an RSAPublicKey from an identity token.

    Args:
        token: The identity token (with config.TOKEN_PREFIX).

    Returns:
        The loaded RSAPublicKey.

    Raises:
        ValueError: If the token is malformed or has the wrong prefix.
    """
    if not token.startswith(config.TOKEN_PREFIX):
        raise ValueError(f"Token must start with prefix '{config.TOKEN_PREFIX}'")

    token_data = token[len(config.TOKEN_PREFIX):]
    # Validate that token_data contains only valid base64 characters
    import string
    valid_b64_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    if not all(c in valid_b64_chars for c in token_data):
        raise ValueError("Invalid base64")

    try:
        public_key_der = base64.b64decode(token_data)
    except Exception:
        raise ValueError("Invalid base64")

    try:
        public_key = serialization.load_der_public_key(public_key_der)
    except Exception:
        raise ValueError("Failed to deserialize public key from DER")

    return public_key

def get_identity_token() -> str:
    """Get the stored identity token.

    Returns:
        The identity token string.

    Raises:
        ValueError: If no identity exists.
    """
    if not has_identity():
        raise ValueError("No identity found. Generate one first.")

    private_key = load_private_key()
    public_key = private_key.public_key()
    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    token = config.TOKEN_PREFIX + base64.b64encode(public_key_der).decode('ascii')
    return token

def get_identity_fingerprint(token: str = None) -> str:
    """Compute the SHA-256 fingerprint of a public key.

    Args:
        token: Optional identity token. If not provided, uses the stored identity.

    Returns:
        Colon-separated uppercase hex pairs (like SSH fingerprint).
    """
    if token is None:
        token = get_identity_token()

    public_key = load_public_key_from_token(token)
    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    fingerprint = hashlib.sha256(public_key_der).hexdigest().upper()
    # Format as colon-separated pairs
    fingerprint = ':'.join([fingerprint[i:i+2] for i in range(0, len(fingerprint), 2)])
    return fingerprint

def has_identity() -> bool:
    """Check if an identity exists (private key file exists)."""
    return os.path.exists(os.path.expanduser(config.PRIVATE_KEY_PATH))

def reset_identity() -> None:
    """Delete the stored private key.

    Raises:
        ValueError: If no identity exists.
    """
    if not has_identity():
        raise ValueError("No identity found to reset.")

    private_key_path = os.path.expanduser(config.PRIVATE_KEY_PATH)
    print("WARNING: This is irreversible. Any files encrypted for this identity will be permanently unreadable.")
    # Ask for confirmation? The spec says print a prominent warning before deletion.
    # We'll just print and then delete. In a real CLI we might ask, but the function just deletes.
    os.remove(private_key_path)