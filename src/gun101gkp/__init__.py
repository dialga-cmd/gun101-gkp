"""GUN-101-GKP: Ghost Key Protocol."""

from . import config  # noqa: F401  (ensure config is loaded for side-effects)
from .cipher import encrypt as aes_encrypt, decrypt as aes_decrypt
from .handler import encrypt_for_recipient, decrypt_as_recipient
from .identity import (
    generate_identity,
    get_identity_token,
    get_identity_fingerprint,
    has_identity,
    reset_identity,
    load_private_key,
    load_public_key_from_token,
)

try:
    from importlib.metadata import version
except ImportError:  # pragma: no cover
    # Python <3.8 fallback
    from importlib_metadata import version  # type: ignore

try:
    __version__ = version('gun101-gkp')
except Exception:  # pragma: no cover
    __version__ = '0.0.0'

__title__ = "gun101gkp"
__description__ = "Passwordless asymmetric encryption using RSA-4096 and AES-256-GCM"
__url__ = "https://github.com/yourusername/gun101-gkp"
__author__ = "Aditya Raj"
__license__ = "MIT"