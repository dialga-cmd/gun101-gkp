PROTOCOL = "GUN-101-GKP"
FORMAT_VERSION = "2.1"
SUPPORTED_FORMAT_VERSIONS = ["2.0", "2.1"]
# FORMAT_VERSION is the version used for new encryptions.
# SUPPORTED_FORMAT_VERSIONS are all format versions this code can decrypt
# for backward compatibility. When FORMAT_VERSION is increased for a real
# container format change, the previous version must be appended to
# SUPPORTED_FORMAT_VERSIONS and never removed.
RSA_KEY_SIZE = 4096
RSA_PUBLIC_EXPONENT = 65537
OAEP_HASH = "SHA-256"
DEK_LEN = 32             # AES-256 key length in bytes
AES_NONCE_LEN = 12
PRIVATE_KEY_PATH = "~/.gun101gkp/private_key.pem"
TOKEN_PREFIX = "GUN101GKP-v2-"