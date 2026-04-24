#!/usr/bin/env python3
"""
resource_fetcher.py

Download a resource from a URL and verify its integrity using the
Content-Digest HTTP header if present.

Supports common digest algorithms such as SHA-256, SHA-512, etc.

Usage:
    python resource_fetcher.py <URL>
"""

import sys
import hashlib
import base64
import requests


def parse_content_digest(header_value: str):
    """
    Parse a Content-Digest header.

    Example header:
        sha-256=:BASE64_DIGEST:

    Returns:
        (algorithm: str, expected_digest_bytes: bytes)
    """
    try:
        algo_part, digest_part = header_value.split("=", 1)
        algo = algo_part.strip().lower()

        # Remove surrounding colons (RFC format :base64:)
        digest_b64 = digest_part.strip().strip(":")
        expected_digest = base64.b64decode(digest_b64)

        return algo, expected_digest

    except Exception as e:
        raise ValueError(f"Invalid Content-Digest header format: {e}")


def compute_digest(content: bytes, algorithm: str) -> bytes:
    """
    Compute the digest of given content using the specified algorithm.

    Supported algorithms depend on hashlib availability.
    """
    algo_map = {
        "sha-256": "sha256",
        "sha-512": "sha512",
        "sha-1": "sha1",
        "md5": "md5",
    }

    if algorithm not in algo_map:
        raise ValueError(f"Unsupported digest algorithm: {algorithm}")

    hash_func = hashlib.new(algo_map[algorithm])
    hash_func.update(content)
    return hash_func.digest()


def download_resource(url: str):
    """
    Download a resource and return its content and headers.
    """
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        return response.content, response.headers
    except requests.RequestException as e:
        raise RuntimeError(f"Download failed: {e}")


def verify_resource(content: bytes, headers: dict) -> bool:
    """
    Verify resource integrity using Content-Digest header if present.

    Returns:
        True if accepted, False if rejected
    """
    content_digest = headers.get("Content-Digest")

    if not content_digest:
        print("No Content-Digest header found. Skipping integrity verification.")
        return True  # Accept by default if no digest is provided

    print(f"Content-Digest header detected: {content_digest}")

    try:
        algorithm, expected_digest = parse_content_digest(content_digest)
        computed_digest = compute_digest(content, algorithm)

        if computed_digest == expected_digest:
            print("Digest verification succeeded.")
            return True
        else:
            print("Digest verification FAILED.")
            return False

    except Exception as e:
        print(f"Verification error: {e}")
        return False


def main():
    """
    Entry point of the script.
    """
    if len(sys.argv) != 2:
        print("Usage: python resource_fetcher.py <URL>")
        sys.exit(1)

    url = sys.argv[1]
    print(f"Downloading resource from: {url}")

    try:
        content, headers = download_resource(url)
        is_valid = verify_resource(content, headers)

        if is_valid:
            print("FINAL RESULT: RESOURCE ACCEPTED")
            sys.exit(0)
        else:
            print("FINAL RESULT: RESOURCE REJECTED")
            sys.exit(2)

    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(3)


if __name__ == "__main__":
    main()
