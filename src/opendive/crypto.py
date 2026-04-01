"""
crypto.py - DIVE cryptographic operations
Handles hashing, signing, and signature verification.

Supported algorithms (per DIVE RFC):
  Signatures : ed25519 (recommended), ed448
  Hashes     : sha256 (recommended), sha384, sha512
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
HashAlgorithm = Literal["sha256", "sha384", "sha512"]

DEFAULT_SIG_ALG: SigAlgorithm = "ed25519"
DEFAULT_HASH_ALG: HashAlgorithm = "sha256"

SUPPORTED_SIG_ALGS: set[str] = {"ed25519", "ed448"}
SUPPORTED_HASH_ALGS: set[str] = {"sha256", "sha384", "sha512"}

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


# ── Hash ──────────────────────────────────────────────────────────────────────


def hash_payload(
    data: bytes,
    algorithm: HashAlgorithm = DEFAULT_HASH_ALG,
) -> str:
    """
    Hash arbitrary bytes using the specified algorithm.
    Returns a lowercase hex digest.

    Supported: sha256 (default), sha384, sha512
    """
    if algorithm not in SUPPORTED_HASH_ALGS:
        raise UnsupportedAlgorithm(
            f"Unsupported hash algorithm: {algorithm!r}. "
            f"Supported: {sorted(SUPPORTED_HASH_ALGS)}",
        )

    h = hashlib.new(algorithm, data)
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
    """
    if algorithm not in SUPPORTED_HASH_ALGS:
        raise UnsupportedAlgorithm(
            f"Unsupported hash algorithm: {algorithm!r}. "
            f"Supported: {sorted(SUPPORTED_HASH_ALGS)}",
        )

    h = hashlib.new(algorithm)
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
    sig_algorithm: SigAlgorithm = DEFAULT_SIG_ALG,
    hash_algorithm: HashAlgorithm = DEFAULT_HASH_ALG,
) -> dict:
    """
    High-level signing function used by the CLI.
    1. Hashes the data.
    2. Signs the hex digest (DIVE RFC requirement).
    3. Returns a dict containing all metadata for the CLI output.
    """
    # Reuse your existing sign_hash logic
    result = sign_hash(
        data,
        private_key_b64,
        sig_algorithm=sig_algorithm,
        hash_algorithm=hash_algorithm,
    )

    # Add the hex_digest specifically for the CLI's --json output and display
    result["hex_digest"] = result["digest"]
    return result


def sign_hash(
    data: bytes,
    private_key_b64: str,
    sig_algorithm: SigAlgorithm = DEFAULT_SIG_ALG,
    hash_algorithm: HashAlgorithm = DEFAULT_HASH_ALG,
) -> dict:
    """
    Hash the payload, then sign the hex digest.
    Returns a dict with the hex digest and the base64 signature.

    Typical DIVE usage: sign_hash(file_bytes, private_key)
    """
    payload = build_signature_input(data, hash_algorithm)
    signature = sign(payload, private_key_b64, sig_algorithm)

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
) -> bool:
    """
    Hash the payload then verify the signature over the hex digest.
    Mirror of sign_hash().
    """
    digest = hash_payload(data, hash_algorithm)
    return verify(digest.encode("utf-8"), signature_b64, public_key_b64, sig_algorithm)


def build_signature_input(data: bytes, algorithm: str) -> bytes:
    """
    Implémentation stricte du RFC DIVE v0.1 §5.5.1
    input = hash_algorithm_name || ":" || hash_bytes_raw
    """
    hasher = hashlib.new(algorithm)
    hasher.update(data)
    hash_bytes_raw = hasher.digest()

    prefix = f"{algorithm}:".encode("ascii")

    return prefix + hash_bytes_raw


def compute_hex_digest(data: bytes, algorithm: HashAlgorithm) -> str:
    """
    Returns the hex digest for reporting and verification steps.
    """
    return hash_payload(data, algorithm)
