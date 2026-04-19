"""
crypto.py - DIVE cryptographic operations
Handles hashing, signing, and signature verification.

Supported algorithms (per DIVE RFC):
  Signatures : ed25519 (recommended), ed448
  Hashes     : sha256 (recommended), sha384, sha512,
               sha3-256, sha3-384, sha3-512
"""

from __future__ import annotations

import base64
import hashlib
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed448 import (
    Ed448PrivateKey,
    Ed448PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# ── Types ─────────────────────────────────────────────────────────────────────

SigAlgorithm = Literal["ed25519", "ed448"]
HashAlgorithm = Literal[
    "sha256", "sha384", "sha512", "sha3-256", "sha3-384", "sha3-512"
]

DEFAULT_SIG_ALG: SigAlgorithm = "ed25519"
DEFAULT_HASH_ALG: HashAlgorithm = "sha256"

SUPPORTED_SIG_ALGS: set[str] = {"ed25519", "ed448"}
SUPPORTED_HASH_ALGS: set[str] = {
    "sha256",
    "sha384",
    "sha512",
    "sha3-256",
    "sha3-384",
    "sha3-512",
}

# ── Exceptions ────────────────────────────────────────────────────────────────


class UnsupportedAlgorithm(Exception):
    pass


class SignatureVerificationFailed(Exception):
    pass


# ── Internal helpers ──────────────────────────────────────────────────────────


def _load_private_key(
    private_b64: str,
    algorithm: SigAlgorithm = DEFAULT_SIG_ALG,
) -> Ed25519PrivateKey | Ed448PrivateKey:
    raw = base64.b64decode(private_b64)
    if algorithm == "ed25519":
        return Ed25519PrivateKey.from_private_bytes(raw)
    if algorithm == "ed448":
        return Ed448PrivateKey.from_private_bytes(raw)
    raise UnsupportedAlgorithm(f"Unknown signature algorithm: {algorithm!r}")


def _load_public_key(
    public_b64: str,
    algorithm: SigAlgorithm = DEFAULT_SIG_ALG,
) -> Ed25519PublicKey | Ed448PublicKey:
    raw = base64.b64decode(public_b64)
    if algorithm == "ed25519":
        return Ed25519PublicKey.from_public_bytes(raw)
    if algorithm == "ed448":
        return Ed448PublicKey.from_public_bytes(raw)
    raise UnsupportedAlgorithm(f"Unknown signature algorithm: {algorithm!r}")


# ── Internal ──────────────────────────────────────────────────────────────────


def _hashlib_name(algorithm: str) -> str:
    """
    Translate a DIVE algorithm name to its hashlib equivalent.
    DIVE uses "sha3-256" while hashlib expects "sha3_256".
    """
    return algorithm.replace("-", "_")


# ── Hash ──────────────────────────────────────────────────────────────────────


def hash_payload(
    data: bytes,
    algorithm: HashAlgorithm = DEFAULT_HASH_ALG,
) -> str:
    """
    Hash arbitrary bytes using the specified algorithm.
    Returns a lowercase hex digest.

    Supported: sha256 (default), sha384, sha512, sha3-256, sha3-384, sha3-512
    """
    if algorithm not in SUPPORTED_HASH_ALGS:
        raise UnsupportedAlgorithm(
            f"Unsupported hash algorithm: {algorithm!r}. "
            f"Supported: {sorted(SUPPORTED_HASH_ALGS)}",
        )

    h = hashlib.new(_hashlib_name(algorithm), data)
    return h.hexdigest()


def hash_file(
    path: str,
    algorithm: HashAlgorithm = DEFAULT_HASH_ALG,
    chunk_size: int = 65536,
) -> str:
    """
    Hash a file on disk using the specified algorithm.
    Reads in chunks to support large files.
    Returns a lowercase hex digest.

    Supported: sha256 (default), sha384, sha512, sha3-256, sha3-384, sha3-512
    """
    if algorithm not in SUPPORTED_HASH_ALGS:
        raise UnsupportedAlgorithm(
            f"Unsupported hash algorithm: {algorithm!r}. "
            f"Supported: {sorted(SUPPORTED_HASH_ALGS)}",
        )

    h = hashlib.new(_hashlib_name(algorithm))
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


# ── Sign ──────────────────────────────────────────────────────────────────────


def sign(
    payload: bytes,
    private_key_b64: str,
    algorithm: SigAlgorithm = DEFAULT_SIG_ALG,
) -> str:
    """
    Sign a payload with the given base64-encoded private key.
    Returns the signature as a base64 string.

    Supported: ed25519 (default), ed448
    """
    if algorithm not in SUPPORTED_SIG_ALGS:
        raise UnsupportedAlgorithm(
            f"Unsupported signature algorithm: {algorithm!r}. "
            f"Supported: {sorted(SUPPORTED_SIG_ALGS)}",
        )

    private_key = _load_private_key(private_key_b64, algorithm)
    signature = private_key.sign(payload)
    return base64.b64encode(signature).decode("utf-8")


def sign_file(
    data: bytes,
    private_key_b64: str,
    key_id: str,
    sig_algorithm: SigAlgorithm = DEFAULT_SIG_ALG,
    hash_algorithm: HashAlgorithm = DEFAULT_HASH_ALG,
) -> dict:
    """
    High-level signing function used by the CLI (DIVE draft-01).
    Constructs RFC 9421 Signature-Input / Signature / Content-Digest headers.
    Returns a dict containing all metadata and header values for the CLI output.
    """
    content_digest_value = build_content_digest(data, hash_algorithm)
    sig_label = f"sig{key_id}"
    sig_base = build_signature_base(content_digest_value, key_id, sig_algorithm)
    signature_b64 = sign(sig_base, private_key_b64, sig_algorithm)

    return {
        "hash_algorithm": hash_algorithm,
        "sig_algorithm": sig_algorithm,
        "hex_digest": compute_hex_digest(data, hash_algorithm),
        "sig_label": sig_label,
        "content_digest_header": content_digest_value,
        "signature_input_header": (
            f'{sig_label}=("content-digest");keyid="{key_id}";alg="{sig_algorithm}"'
        ),
        "signature_header": f"{sig_label}=:{signature_b64}:",
        "signature": signature_b64,
    }


def sign_hash(
    data: bytes,
    private_key_b64: str,
    sig_algorithm: SigAlgorithm = DEFAULT_SIG_ALG,
    hash_algorithm: HashAlgorithm = DEFAULT_HASH_ALG,
    key_id: str = "key1",
) -> dict:
    """
    Hash the payload and sign using the RFC 9421 signature base.
    Returns a dict with the hex digest and the base64 signature.

    Typical DIVE usage: sign_hash(file_bytes, private_key)
    """
    content_digest_value = build_content_digest(data, hash_algorithm)
    sig_base = build_signature_base(content_digest_value, key_id, sig_algorithm)
    signature = sign(sig_base, private_key_b64, sig_algorithm)

    return {
        "hash_algorithm": hash_algorithm,
        "digest": compute_hex_digest(data, hash_algorithm),
        "sig_algorithm": sig_algorithm,
        "signature": signature,
    }


# ── Verify ────────────────────────────────────────────────────────────────────


def verify(
    payload: bytes,
    signature_b64: str,
    public_key_b64: str,
    algorithm: SigAlgorithm = DEFAULT_SIG_ALG,
) -> bool:
    """
    Verify a base64 signature over a raw payload.
    Returns True on success, raises SignatureVerificationFailed on failure.
    """
    if algorithm not in SUPPORTED_SIG_ALGS:
        raise UnsupportedAlgorithm(
            f"Unsupported signature algorithm: {algorithm!r}. "
            f"Supported: {sorted(SUPPORTED_SIG_ALGS)}",
        )

    public_key = _load_public_key(public_key_b64, algorithm)
    signature = base64.b64decode(signature_b64)

    try:
        public_key.verify(signature, payload)
        return True
    except InvalidSignature:
        raise SignatureVerificationFailed(
            f"Signature verification failed (algorithm={algorithm!r})",
        )


def verify_hash(
    data: bytes,
    signature_b64: str,
    public_key_b64: str,
    sig_algorithm: SigAlgorithm = DEFAULT_SIG_ALG,
    hash_algorithm: HashAlgorithm = DEFAULT_HASH_ALG,
    key_id: str = "key1",
) -> bool:
    """
    Hash the payload then verify the RFC 9421 signature.
    Mirror of sign_hash().
    """
    content_digest_value = build_content_digest(data, hash_algorithm)
    sig_base = build_signature_base(content_digest_value, key_id, sig_algorithm)
    return verify(sig_base, signature_b64, public_key_b64, sig_algorithm)


# ── RFC 9421 / RFC 9530 helpers ───────────────────────────────────────────────

# Maps DIVE canonical hash names → RFC 9530 Content-Digest algorithm names
_RFC9530_ALG: dict[str, str] = {
    "sha256": "sha-256",
    "sha384": "sha-384",
    "sha512": "sha-512",
    "sha3-256": "sha3-256",
    "sha3-384": "sha3-384",
    "sha3-512": "sha3-512",
}

# Reverse: RFC 9530 names → DIVE canonical names
_DIVE_ALG_FROM_RFC9530: dict[str, str] = {v: k for k, v in _RFC9530_ALG.items()}


def build_content_digest(data: bytes, algorithm: HashAlgorithm) -> str:
    """
    Compute the RFC 9530 Content-Digest header value.
    Returns e.g. 'sha-256=:BASE64DIGEST:'
    """
    if algorithm not in _RFC9530_ALG:
        raise UnsupportedAlgorithm(f"Unsupported hash algorithm: {algorithm!r}")
    hasher = hashlib.new(_hashlib_name(algorithm))
    hasher.update(data)
    digest_b64 = base64.b64encode(hasher.digest()).decode("ascii")
    return f"{_RFC9530_ALG[algorithm]}=:{digest_b64}:"


def build_signature_base(
    content_digest_value: str,
    key_id: str,
    sig_algorithm: str,
) -> bytes:
    """
    Construct the RFC 9421 signature base covering content-digest.

    Format (per RFC 9421 §2.5):
      "content-digest": <value>\\n"@signature-params": <params>
    """
    sig_params = f'("content-digest");keyid="{key_id}";alg="{sig_algorithm}"'
    base = (
        f'"content-digest": {content_digest_value}\n'
        f'"@signature-params": {sig_params}'
    )
    return base.encode("utf-8")


def compute_hex_digest(data: bytes, algorithm: HashAlgorithm) -> str:
    """
    Returns the hex digest for reporting and verification steps.
    """
    return hash_payload(data, algorithm)
