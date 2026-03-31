# tests/crypto_test.py

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1] / "src"))

from dive.crypto import (
    DEFAULT_HASH_ALG,
    DEFAULT_SIG_ALG,
    SUPPORTED_HASH_ALGS,
    SUPPORTED_SIG_ALGS,
    SignatureVerificationFailed,
    UnsupportedAlgorithm,
    hash_file,
    hash_payload,
    sign,
    sign_hash,
    verify,
    verify_hash,
)
from dive.keys import generate_base64_keypair

# ── Helpers ───────────────────────────────────────────────────────────────────

PAYLOAD = b"Hello, DIVE protocol!"


def section(title: str):
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}")


def ok(label: str):
    print(f"  [OK] {label}")


def fail(label: str, err: Exception):
    print(f"  [FAIL] {label}: {err}")


# ── Hash tests ────────────────────────────────────────────────────────────────

section("hash_payload — all supported algorithms")
for alg in sorted(SUPPORTED_HASH_ALGS):
    digest = hash_payload(PAYLOAD, alg)
    ok(f"{alg}: {digest}")

section("hash_payload — default algorithm")
digest_default = hash_payload(PAYLOAD)
ok(f"default ({DEFAULT_HASH_ALG}): {digest_default}")

section("hash_payload — unsupported algorithm")
try:
    hash_payload(PAYLOAD, "md5")  # type: ignore
    fail("md5", Exception("should have raised"))
except UnsupportedAlgorithm as e:
    ok(f"Correctly rejected: {e}")

section("hash_file — write tmp file and hash it")
tmp = Path("/tmp/dive_test_payload.bin")
tmp.write_bytes(PAYLOAD)
for alg in sorted(SUPPORTED_HASH_ALGS):
    digest_file = hash_file(str(tmp), alg)
    digest_payload = hash_payload(PAYLOAD, alg)
    assert digest_file == digest_payload, f"Mismatch for {alg}"
    ok(f"{alg}: consistent with hash_payload")

# ── Sign / Verify tests ───────────────────────────────────────────────────────

for sig_alg in sorted(SUPPORTED_SIG_ALGS):
    section(f"sign + verify — {sig_alg}")

    keypair = generate_base64_keypair(sig_alg)
    priv = keypair["private_key"]
    pub = keypair["public_key"]

    # Raw sign/verify
    sig = sign(PAYLOAD, priv, sig_alg)
    ok(f"signature: {sig[:40]}…")

    result = verify(PAYLOAD, sig, pub, sig_alg)
    ok(f"verify returned: {result}")

    # Tampered payload
    section(f"verify tampered payload — {sig_alg}")
    try:
        verify(b"tampered payload!", sig, pub, sig_alg)
        fail("tampered payload", Exception("should have raised"))
    except SignatureVerificationFailed as e:
        ok(f"Correctly rejected: {e}")

    # sign_hash / verify_hash
    for hash_alg in sorted(SUPPORTED_HASH_ALGS):
        section(f"sign_hash + verify_hash — {sig_alg} / {hash_alg}")

        result_dict = sign_hash(PAYLOAD, priv, sig_alg, hash_alg)
        ok(f"digest    : {result_dict['digest'][:40]}…")
        ok(f"signature : {result_dict['signature'][:40]}…")

        valid = verify_hash(PAYLOAD, result_dict["signature"], pub, sig_alg, hash_alg)
        ok(f"verify_hash returned: {valid}")

# ── Default parameters ────────────────────────────────────────────────────────

section(f"sign_hash — defaults ({DEFAULT_SIG_ALG} / {DEFAULT_HASH_ALG})")
keypair = generate_base64_keypair()
result = sign_hash(PAYLOAD, keypair["private_key"])
ok(f"hash_algorithm : {result['hash_algorithm']}")
ok(f"sig_algorithm  : {result['sig_algorithm']}")
ok(f"digest         : {result['digest']}")
ok(f"signature      : {result['signature'][:40]}…")

valid = verify_hash(PAYLOAD, result["signature"], keypair["public_key"])
ok(f"verify_hash (defaults) returned: {valid}")

section("All crypto tests passed ✓")
