import base64
from typing import Dict, Union

from cryptography.hazmat.primitives.asymmetric import ed448, ed25519

# Mapping of supported Edwards-curve Digital Signature Algorithms (EdDSA)
SUPPORTED_ALGORITHMS = {
    "ed25519": ed25519.Ed25519PrivateKey,
    "ed448": ed448.Ed448PrivateKey,
}

DEFAULT_ALGORITHM = "ed25519"


def generate_key(alg: str = DEFAULT_ALGORITHM) -> Dict[str, Union[str, any]]:
    """
    Generates a new asymmetric key pair using the specified EdDSA algorithm.

    Args:
        alg (str): The algorithm to use ('ed25519' or 'ed448').
                   Defaults to 'ed25519' for optimal performance/compatibility.

    Returns:
        dict: A dictionary containing the algorithm name, and the raw
              private/public key objects.

    Raises:
        ValueError: If the requested algorithm is not supported.
    """
    alg = alg.lower()

    if alg not in SUPPORTED_ALGORITHMS:
        raise ValueError(
            f"Unsupported algorithm: '{alg}'. Supported: {list(SUPPORTED_ALGORITHMS.keys())}"
        )

    # Generate the private key using the cryptography library provider
    private_key = SUPPORTED_ALGORITHMS[alg].generate()
    public_key = private_key.public_key()

    return {
        "algorithm": alg,
        "private_key": private_key,
        "public_key": public_key,
    }


def export_private_key_base64(private_key) -> str:
    """
    Serializes a private key object into a Base64-encoded string.
    Exports seed || public_key (64 bytes for Ed25519, 114 for Ed448).
    """
    seed = private_key.private_bytes_raw()
    pub = private_key.public_key().public_bytes_raw()
    return base64.b64encode(seed + pub).decode("utf-8")


def export_public_key_base64(public_key) -> str:
    """
    Serializes a public key object into a Base64-encoded string.
    Useful for sharing keys in JSON or web-based environments.
    """
    raw = public_key.public_bytes_raw()
    return base64.b64encode(raw).decode("utf-8")


def generate_base64_keypair(alg: str = DEFAULT_ALGORITHM) -> Dict[str, str]:
    """
    High-level utility to generate a ready-to-use Base64 encoded key pair.

    This is the primary entry point for applications requiring
    string-represented keys for storage or transmission.

    Args:
        alg (str): The desired algorithm.

    Returns:
        dict: A dictionary containing 'algorithm', 'private_key', and 'public_key'
              as UTF-8 strings.
    """
    keys = generate_key(alg)

    return {
        "algorithm": keys["algorithm"],
        "private_key": export_private_key_base64(keys["private_key"]),
        "public_key": export_public_key_base64(keys["public_key"]),
    }
