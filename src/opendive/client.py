"""
client.py - OpenDIVE verification engine

Implements the six-step client algorithm defined in the DIVE RFC §5:

  Step 1 — Policy discovery
  Step 2 — Scope determination
  Step 3 — Header validation
  Step 4 — Key resolution
  Step 5 — Signature verification
  Step 6 — Enforcement and reporting

Usage example::

    client = DiveClient()
    result = client.verify("https://example.com/file.tar.gz")
    if result.accepted:
        print("Resource is authentic!")
    else:
        print(f"DIVE rejected resource: {result.failure_reason}")
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

from .crypto import (
    _DIVE_ALG_FROM_RFC9530,
    _hashlib_name,
    build_signature_base,
)
from .dns import (
    DiveRecordInvalid,
    DiveRecordNotFound,
    get_dive_record_walk,
    get_key_record,
)

# ── Constants ─────────────────────────────────────────────────────────────────

ALLOWED_HASH_ALGS = {"sha256", "sha384", "sha512", "sha3-256", "sha3-384", "sha3-512"}
REPORT_VERSION = "0.1"

# Failure reason strings (RFC §6)
FR_MISSING_HEADERS = "missing-headers"
FR_KEY_NOT_FOUND = "key-not-found"
FR_KEY_INVALID = "key-invalid"
FR_DNSSEC_UNAVAILABLE = "dnssec-unavailable"
FR_HASH_NOT_ALLOWED = "hash-algorithm-not-allowed"
FR_SIGNATURE_MISMATCH = "signature-mismatch"
FR_NO_VALID_KEY = "no-valid-key"

# ── Data classes ──────────────────────────────────────────────────────────────


@dataclass
class KeyResolutionEntry:
    key_id: str
    fqdn_queried: str | None = None
    found: bool = False
    dnssec_validated: bool = False
    sig_algorithm: str | None = None


@dataclass
class VerificationResult:
    """Outcome of a DIVE verification attempt."""

    url: str
    accepted: bool
    report_only: bool = False
    failure_reason: str | None = None
    final_decision: str | None = None  # "blocked" | "allowed-report-only"
    scope: str | None = None
    hash_algorithm: str | None = None
    hex_digest: str | None = None
    signature_valid: bool = False
    key_resolution: list[KeyResolutionEntry] = field(default_factory=list)
    signature_input_header: str | None = None
    content_digest_header: str | None = None
    dnssec_validated: bool = False
    policy_domain: str | None = None
    policy_fqdn: str | None = None
    body: bytes | None = None  # Only set on success

    def to_report(self, user_agent: str = "opendive-client/0.1") -> dict:
        """Serialise a failure report per RFC §6."""
        return {
            "report-version": REPORT_VERSION,
            "timestamp": int(time.time()),
            "client": {
                "user-agent": user_agent,
            },
            "policy": {
                "domain": self.policy_domain,
                "fqdn": self.policy_fqdn,
                "dnssec-validated": self.dnssec_validated,
            },
            "resource": {
                "url": self.url,
                "method": "GET",
                "status-code": 200,
                "scope": self.scope,
            },
            "headers-received": {
                "signature-input": self.signature_input_header,
                "content-digest": self.content_digest_header,
            },
            "key-resolution": [
                {
                    "key-id": e.key_id,
                    "fqdn-queried": e.fqdn_queried,
                    "found": e.found,
                    "dnssec-validated": e.dnssec_validated,
                    "sig-algorithm": e.sig_algorithm,
                }
                for e in self.key_resolution
            ],
            "validation": {
                "hash-algorithm": self.hash_algorithm,
                "hash-computed": (
                    base64.b64encode(bytes.fromhex(self.hex_digest)).decode()
                    if self.hex_digest
                    else None
                ),
                "signature-valid": self.signature_valid,
                "failure-reason": self.failure_reason,
                "final-decision": self.final_decision,
            },
        }


# ── RFC 9421 / RFC 9530 header parsing ───────────────────────────────────────


@dataclass
class SigEntry:
    key_id: str
    sig_label: str             # label from Signature-Input (e.g. "sigABC")
    sig_algorithm: str         # from alg param
    signature: str             # base64 from Signature header
    content_digest_value: str  # full Content-Digest header value
    hash_algorithm: str        # DIVE canonical name derived from Content-Digest alg
    raw_sig_params: str = ""   # exact dict-value string from Signature-Input for RFC 9421 base
    fqdn_qualifier: str | None = None  # optional @fqdn suffix stripped from keyid


def _parse_content_digest(header_value: str) -> tuple[str, str] | None:
    """
    Parse the first entry of a Content-Digest header (RFC 9530).
    Returns (dive_hash_algorithm, full_header_value) or None on failure.

    Accepts e.g. 'sha-256=:BASE64:' or 'sha-256=:B64:, sha-512=:B64:'
    """
    # Take the first algorithm entry
    m = re.match(r"\s*([\w-]+)\s*=\s*:([A-Za-z0-9+/=]+):", header_value)
    if not m:
        return None
    rfc_alg = m.group(1).lower()
    dive_alg = _DIVE_ALG_FROM_RFC9530.get(rfc_alg)
    if dive_alg is None:
        return None
    return dive_alg, header_value.strip()


def _parse_rfc9421_headers(
    sig_input_header: str,
    sig_header: str,
    content_digest_header: str,
) -> list[SigEntry]:
    """
    Parse Signature-Input and Signature headers (RFC 9421) together with the
    Content-Digest header (RFC 9530) into a list of SigEntry objects.

    Multiple signatures are expressed as multiple labeled entries in the same
    headers, e.g.:
      Signature-Input: sigA=("content-digest");keyid="k1";alg="ed25519", sigB=...
      Signature: sigA=:BASE64:, sigB=:BASE64:
    """
    # Parse Signature-Input: label -> (keyid, alg, raw_params_string)
    sig_input_entries: dict[str, tuple[str, str, str]] = {}
    # Match: label=("content-digest");keyid="...";alg="..."
    for m in re.finditer(
        r'([\w-]+)\s*=\s*\("content-digest"\)\s*;keyid\s*=\s*"([^"]+)"\s*;alg\s*=\s*"([^"]+)"',
        sig_input_header,
    ):
        label = m.group(1)
        keyid = m.group(2)
        alg = m.group(3).lower()
        raw_params = m.group(0).split("=", 1)[1].strip()
        sig_input_entries[label] = (keyid, alg, raw_params)

    # Parse Signature: label -> base64 value
    sig_values: dict[str, str] = {}
    for m in re.finditer(r"([\w-]+)\s*=\s*:([A-Za-z0-9+/=]+):", sig_header):
        sig_values[m.group(1)] = m.group(2)

    # Parse Content-Digest
    cd_result = _parse_content_digest(content_digest_header)
    if cd_result is None:
        return []
    dive_hash_alg, cd_value = cd_result

    entries: list[SigEntry] = []
    seen_key_ids: set[str] = set()

    for label, (raw_keyid, sig_alg, raw_params) in sig_input_entries.items():
        if label not in sig_values:
            continue

        # Strip optional @fqdn qualifier from the keyid
        if "@" in raw_keyid:
            key_id, fqdn_qualifier = raw_keyid.split("@", 1)
        else:
            key_id, fqdn_qualifier = raw_keyid, None

        if key_id in seen_key_ids:
            continue  # RFC: ignore duplicate Key IDs after first occurrence
        seen_key_ids.add(key_id)

        entries.append(
            SigEntry(
                key_id=key_id,
                sig_label=label,
                sig_algorithm=sig_alg,
                signature=sig_values[label],
                content_digest_value=cd_value,
                hash_algorithm=dive_hash_alg,
                raw_sig_params=raw_params,
                fqdn_qualifier=fqdn_qualifier,
            )
        )

    return entries


# ── Scope detection ───────────────────────────────────────────────────────────


def _is_in_scope(scope: str, response_headers: dict) -> bool:
    """
    Determine whether a resource falls within a given scope.
    Custom scopes (x-*) are always False for a generic client.
    """
    if scope == "strict":
        return True
    if scope.startswith("x-"):
        return False  # Custom scopes: application-defined, unknown → ignore
    return False


# ── Cache (simple in-memory, no persistence) ──────────────────────────────────


class _SimpleCache:
    """Very small in-memory TTL cache for policy and key records."""

    def __init__(self) -> None:
        self._store: dict[str, tuple[object, float]] = {}

    def get(self, key: str) -> object | None:
        if key not in self._store:
            return None
        value, expires_at = self._store[key]
        if time.time() > expires_at:
            del self._store[key]
            return None
        return value

    def set(self, key: str, value: object, ttl_seconds: int) -> None:
        if ttl_seconds <= 0:
            return
        self._store[key] = (value, time.time() + min(ttl_seconds, 86400))

    def delete(self, key: str) -> None:
        self._store.pop(key, None)

    def invalidate_keys_before(self, domain_prefix: str, timestamp: int) -> None:
        """Evict all key records for domain_prefix stored before timestamp."""
        to_delete = [
            k
            for k, (_, exp) in self._store.items()
            if k.startswith(f"key:{domain_prefix}") and exp <= timestamp
        ]
        for k in to_delete:
            del self._store[k]


# ── Main client ───────────────────────────────────────────────────────────────


class DiveClient:
    """
    DIVE verification client.

    Parameters
    ----------
    custom_dns:
        Optional IP address of a DNS resolver to use (overrides system default).
    require_dnssec:
        If True (recommended for production), records without DNSSEC validation
        are treated as absent.  Set to False for local/PoC testing where DNSSEC
        is not available.
    user_agent:
        User-Agent string sent in HTTP requests and failure reports.
    http_timeout:
        Timeout in seconds for HTTP requests.
    """

    def __init__(
        self,
        custom_dns: str | None = None,
        require_dnssec: bool = False,
        user_agent: str = "OpenDIVE-Client/0.1",
        http_timeout: float = 30.0,
    ) -> None:
        self.custom_dns = custom_dns
        self.require_dnssec = require_dnssec
        self.user_agent = user_agent
        self._cache = _SimpleCache()
        self._http = httpx.Client(
            timeout=http_timeout,
            follow_redirects=True,
            headers={"User-Agent": user_agent},
        )

    # ── Step 1: Policy discovery ──────────────────────────────────────────────

    def _get_policy(self, fqdn: str) -> dict | None:
        """
        Retrieve the applicable _dive policy record for fqdn.
        Returns None if DIVE is not supported for this domain.
        """
        cache_key = f"policy:{fqdn}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached  # type: ignore[return-value]

        try:
            records = get_dive_record_walk(fqdn, self.custom_dns)
        except Exception:
            return None

        if not records:
            return None

        policy = records[0]

        if self.require_dnssec and not policy.get("_dnssec_validated"):
            return None

        ttl = int(policy.get("cache", 0))
        if ttl > 0:
            self._cache.set(cache_key, policy, ttl)

        # Apply invalidate-keys-cache if present
        inv_ts = policy.get("invalidate-keys-cache")
        if inv_ts:
            try:
                self._cache.invalidate_keys_before(fqdn, int(inv_ts))
            except (ValueError, TypeError):
                pass

        return policy

    # ── Step 4: Key resolution ────────────────────────────────────────────────

    def _resolve_key(
        self,
        entry: SigEntry,
        resource_fqdn: str,
        policy_fqdn: str,
    ) -> tuple[dict | None, KeyResolutionEntry]:
        """
        Resolve one SigEntry to a key record.
        Returns (key_record_or_None, resolution_log_entry).
        """
        log = KeyResolutionEntry(key_id=entry.key_id)

        # If a @fqdn qualifier is present, validate it is the resource origin or
        # a parent, then use it as the walk starting point.
        if entry.fqdn_qualifier:
            if not (
                resource_fqdn == entry.fqdn_qualifier
                or resource_fqdn.endswith("." + entry.fqdn_qualifier)
            ):
                log.found = False
                return None, log
            start_fqdn = entry.fqdn_qualifier
        else:
            start_fqdn = resource_fqdn

        # Walk upward up to (and including) the policy domain
        from .dns import _domain_walk  # local import to avoid circular

        fqdn_parts = [start_fqdn]
        for d in _domain_walk(start_fqdn):
            if d not in fqdn_parts:
                fqdn_parts.append(d)
            if d == policy_fqdn:
                break

        cache_key = f"key:{resource_fqdn}:{entry.key_id}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            key_rec = cached  # type: ignore[assignment]
            log.found = True
            log.dnssec_validated = key_rec.get("_dnssec_validated", False)
            log.sig_algorithm = key_rec.get("sig")
            log.fqdn_queried = key_rec.get("_fqdn")
            return key_rec, log  # type: ignore[return-value]

        for domain in fqdn_parts:
            try:
                key_records = get_key_record(domain, entry.key_id, self.custom_dns)
            except DiveRecordNotFound:
                continue
            except DiveRecordInvalid:
                log.found = True
                log.fqdn_queried = f"{entry.key_id}._divekey.{domain}"
                return None, log

            if not key_records:
                continue

            key_rec = key_records[0]
            log.found = True
            log.dnssec_validated = key_rec.get("_dnssec_validated", False)
            log.sig_algorithm = key_rec.get("sig")
            log.fqdn_queried = key_rec.get("_fqdn")

            if self.require_dnssec and not log.dnssec_validated:
                return None, log

            ttl = int(key_rec.get("cache", 0))
            if ttl > 0:
                self._cache.set(cache_key, key_rec, ttl)

            return key_rec, log

        log.fqdn_queried = f"{entry.key_id}._divekey.{start_fqdn}"
        return None, log

    # ── Step 5: Signature verification ───────────────────────────────────────

    def _verify_entry(
        self,
        body: bytes,
        entry: SigEntry,
        key_rec: dict,
    ) -> bool:
        """
        Verify one RFC 9421 signature entry against the downloaded body.
        1. Checks allowed-hash constraint.
        2. Verifies Content-Digest matches the body.
        3. Verifies the RFC 9421 signature over the signature base.
        Returns True on success, False on any failure.
        """
        # Check allowed-hash constraint
        if "allowed-hash" in key_rec:
            if entry.hash_algorithm not in key_rec["allowed-hash"]:
                return False

        sig_algorithm = key_rec.get("sig", "ed25519")
        # Honour the algorithm declared in Signature-Input (must match key record)
        if entry.sig_algorithm != sig_algorithm:
            return False

        public_key_b64 = key_rec.get("key")
        if not public_key_b64:
            return False

        # Verify Content-Digest matches body
        import re as _re

        m = _re.match(
            r"\s*[\w-]+=:([A-Za-z0-9+/=]+):", entry.content_digest_value
        )
        if not m:
            return False
        expected_digest_b64 = m.group(1)
        hasher = hashlib.new(_hashlib_name(entry.hash_algorithm))
        hasher.update(body)
        actual_digest_b64 = base64.b64encode(hasher.digest()).decode("ascii")
        if actual_digest_b64 != expected_digest_b64:
            return False

        # Build RFC 9421 signature base using the raw params string exactly as
        # it appeared in Signature-Input (RFC 9421 §2.5).
        sig_base = (
            f'"content-digest": {entry.content_digest_value}\n'
            f'"@signature-params": {entry.raw_sig_params}'
        ).encode("utf-8")


        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        try:
            raw_pub = base64.b64decode(public_key_b64)
            if sig_algorithm == "ed25519":
                pub = Ed25519PublicKey.from_public_bytes(raw_pub)
            elif sig_algorithm == "ed448":
                pub = Ed448PublicKey.from_public_bytes(raw_pub)
            else:
                return False

            raw_sig = base64.b64decode(entry.signature)
            pub.verify(raw_sig, sig_base)
            return True
        except Exception:
            return False

    # ── Main verify method ────────────────────────────────────────────────────

    def verify(self, url: str) -> VerificationResult:
        """
        Execute the full DIVE verification algorithm for the given URL.

        Downloads the resource, resolves DNS records, and verifies the
        cryptographic signature per the RFC algorithm.

        Returns a VerificationResult.  If `accepted` is True the body is
        available in `result.body`.
        """
        parsed = urlparse(url)
        fqdn = parsed.hostname or ""

        result = VerificationResult(url=url, accepted=False)

        # ── HTTP request ──────────────────────────────────────────────────────
        try:
            resp = self._http.get(url)
        except httpx.RequestError:
            result.failure_reason = FR_MISSING_HEADERS
            result.final_decision = "blocked"
            return result

        if resp.status_code != 200:
            result.failure_reason = FR_MISSING_HEADERS
            result.final_decision = "blocked"
            return result

        body = resp.content
        # Build a normalised lower-case header dict from multi_items
        try:
            header_items = resp.headers.multi_items()
        except (AttributeError, TypeError):
            header_items = list(resp.headers.items())
        headers = {k.lower(): v for k, v in header_items}

        # ── Step 1: Policy discovery ──────────────────────────────────────────
        policy = self._get_policy(fqdn)
        if policy is None:
            # DIVE not supported — accept resource
            result.accepted = True
            result.body = body
            return result

        result.policy_domain = policy.get("_fqdn", "").replace("_dive.", "")
        result.policy_fqdn = fqdn
        result.dnssec_validated = policy.get("_dnssec_validated", False)

        report_only = "report-only" in policy.get("directives", [])
        https_required = "https-required" in policy.get("directives", [])

        # https-required check
        if https_required and parsed.scheme != "https":
            result.failure_reason = FR_MISSING_HEADERS
            result.final_decision = "blocked"
            return result

        # ── Step 2: Scope determination ───────────────────────────────────────
        scopes = policy.get("scopes", [])
        matched_scope: str | None = None
        for scope in scopes:
            if _is_in_scope(scope, headers):
                matched_scope = scope
                break

        result.scope = matched_scope

        if matched_scope is None:
            # Not in any declared scope — accept without verification
            result.accepted = True
            result.body = body
            return result

        # ── Step 3: Header validation ─────────────────────────────────────────
        # Collect RFC 9421 headers (concatenate duplicates per RFC 9421 §4.2)
        sig_input_value: str | None = None
        sig_value: str | None = None
        content_digest_value: str | None = None

        for k, v in resp.headers.multi_items():
            kl = k.lower()
            if kl == "signature-input":
                sig_input_value = (sig_input_value + ", " + v) if sig_input_value else v
            elif kl == "signature":
                sig_value = (sig_value + ", " + v) if sig_value else v
            elif kl == "content-digest":
                content_digest_value = (
                    (content_digest_value + ", " + v) if content_digest_value else v
                )

        result.signature_input_header = sig_input_value
        result.content_digest_header = content_digest_value
        result.report_only = report_only

        if not sig_input_value or not sig_value or not content_digest_value:
            result.failure_reason = FR_MISSING_HEADERS
            result.final_decision = "allowed-report-only" if report_only else "blocked"
            self._maybe_report(result, policy)
            if not report_only:
                return result
            result.accepted = True
            result.body = body
            return result

        try:
            sig_entries = _parse_rfc9421_headers(
                sig_input_value, sig_value, content_digest_value
            )
        except Exception:
            result.failure_reason = FR_MISSING_HEADERS
            result.final_decision = "allowed-report-only" if report_only else "blocked"
            self._maybe_report(result, policy)
            if not report_only:
                return result
            result.accepted = True
            result.body = body
            return result

        if not sig_entries:
            result.failure_reason = FR_MISSING_HEADERS
            result.final_decision = "allowed-report-only" if report_only else "blocked"
            self._maybe_report(result, policy)
            if not report_only:
                return result
            result.accepted = True
            result.body = body
            return result

        # ── Steps 4 + 5: Key resolution and signature verification ────────────
        policy_base_fqdn = policy.get("_fqdn", "").replace("_dive.", "", 1)

        all_key_logs: list[KeyResolutionEntry] = []
        any_success = False

        for entry in sig_entries:
            result.hash_algorithm = entry.hash_algorithm
            # Compute hex digest for reporting
            hasher = hashlib.new(_hashlib_name(entry.hash_algorithm))
            hasher.update(body)
            result.hex_digest = hasher.hexdigest()

            key_rec, log = self._resolve_key(entry, fqdn, policy_base_fqdn)
            all_key_logs.append(log)

            if key_rec is None:
                if not log.found:
                    result.failure_reason = FR_KEY_NOT_FOUND
                else:
                    result.failure_reason = (
                        FR_DNSSEC_UNAVAILABLE if self.require_dnssec else FR_KEY_INVALID
                    )
                continue

            ok = self._verify_entry(body, entry, key_rec)
            if ok:
                result.signature_valid = True
                any_success = True
                break
            result.failure_reason = FR_SIGNATURE_MISMATCH

        result.key_resolution = all_key_logs

        if any_success:
            result.accepted = True
            result.final_decision = None
            result.body = body
            return result

        # All entries failed
        if not result.failure_reason:
            result.failure_reason = FR_NO_VALID_KEY

        result.final_decision = "allowed-report-only" if report_only else "blocked"
        self._maybe_report(result, policy)

        if report_only:
            result.accepted = True
            result.body = body

        return result

    # ── Step 6: Reporting ─────────────────────────────────────────────────────

    def _maybe_report(self, result: VerificationResult, policy: dict) -> None:
        """Send a failure report to report-to if configured."""
        report_url = policy.get("report-to")
        if not report_url:
            return
        if not report_url.startswith("https://"):
            return  # RFC: plain HTTP URLs MUST be ignored

        try:
            payload = result.to_report(self.user_agent)
            self._http.post(
                report_url,
                content=json.dumps(payload),
                headers={"Content-Type": "application/json"},
                timeout=5.0,
            )
        except Exception:
            pass  # RFC: report failures MUST NOT affect resource acceptance

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> DiveClient:
        return self

    def __exit__(self, *_) -> None:
        self.close()
