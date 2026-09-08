# Copyright (c) 2026 Security Team
# SPDX-License-Identifier: MIT

"""GUN-101-GKP: Ghost Key Protocol."""

from . import config  # noqa: F401  (ensure config is loaded for side-effects)
from .cipher import decrypt as aes_decrypt
from .cipher import encrypt as aes_encrypt
from .handler import decrypt_as_recipient, encrypt_for_recipient
from .identity import (
    generate_identity,
    get_identity_fingerprint,
    get_identity_token,
    has_identity,
    load_private_key,
    load_public_key_from_token,
    reset_identity,
)

__all__ = [
    "generate_identity",
    "get_identity_token",
    "get_identity_fingerprint",
    "has_identity",
    "reset_identity",
    "load_private_key",
    "load_public_key_from_token",
    "encrypt_for_recipient",
    "decrypt_as_recipient",
    "aes_encrypt",
    "aes_decrypt",
]

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
__url__ = "https://github.com/dialga-cmd/gun101-gkp"
__author__ = "Aditya Raj"
__license__ = "MIT"
