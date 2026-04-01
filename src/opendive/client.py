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
import json
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

from .crypto import (
    build_signature_input,
    compute_hex_digest,
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
    dive_sig_header: str | None = None
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
                "dive-sig": self.dive_sig_header,
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


# ── DIVE-Sig header parsing ───────────────────────────────────────────────────


@dataclass
class SigEntry:
    key_id: str
    fqdn_qualifier: str | None
    hash_algorithm: str
    signature: str


def _parse_dive_sig(header_value: str) -> list[SigEntry]:
    """
    Parse the DIVE-Sig header value into a list of SigEntry objects.

    Format per RFC §3.1:
      keyID:hash-algorithm:BASE64SIG
      keyID@fqdn:hash-algorithm:BASE64SIG
    Multiple entries are comma-separated.
    """
    entries: list[SigEntry] = []
    seen_key_ids: set[str] = set()

    for raw_entry in header_value.split(","):
        raw_entry = raw_entry.strip()
        if not raw_entry:
            continue

        parts = raw_entry.split(":")
        # Minimum 3 colon-separated parts; base64 may itself contain no colons
        # Format: <key_part>:<hash_alg>:<signature>
        # key_part may be "keyID" or "keyID@fqdn"
        if len(parts) < 3:
            raise ValueError(f"Malformed DIVE-Sig entry: {raw_entry!r}")

        key_part = parts[0]
        hash_alg = parts[1].lower()
        signature = ":".join(
            parts[2:]
        )  # re-join in case base64 had colons (shouldn't, but defensive)

        if hash_alg not in ALLOWED_HASH_ALGS:
            raise ValueError(f"Unsupported hash algorithm in DIVE-Sig: {hash_alg!r}")

        fqdn_qualifier: str | None = None
        if "@" in key_part:
            key_id, fqdn_qualifier = key_part.split("@", 1)
        else:
            key_id = key_part

        if key_id in seen_key_ids:
            continue  # RFC: ignore duplicate Key IDs after first occurrence
        seen_key_ids.add(key_id)

        entries.append(
            SigEntry(
                key_id=key_id,
                fqdn_qualifier=fqdn_qualifier,
                hash_algorithm=hash_alg,
                signature=signature,
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
        user_agent: str = "opendive-client/0.1",
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
        Resolve one DIVE-Sig entry to a key record.
        Returns (key_record_or_None, resolution_log_entry).
        """
        log = KeyResolutionEntry(key_id=entry.key_id)

        # Determine starting FQDN
        if entry.fqdn_qualifier:
            # Validate: qualifier must be resource origin or a parent
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
        Verify one DIVE-Sig entry against the downloaded body.
        Returns True on success, False on any failure.
        """
        # Check allowed-hash constraint
        if "allowed-hash" in key_rec:
            if entry.hash_algorithm not in key_rec["allowed-hash"]:
                return False

        sig_algorithm = key_rec.get("sig", "ed25519")
        public_key_b64 = key_rec.get("key")
        if not public_key_b64:
            return False

        sig_input = build_signature_input(body, entry.hash_algorithm)  # type: ignore[arg-type]

        import base64 as _base64

        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        try:
            raw_pub = _base64.b64decode(public_key_b64)
            if sig_algorithm == "ed25519":
                pub = Ed25519PublicKey.from_public_bytes(raw_pub)
            elif sig_algorithm == "ed448":
                pub = Ed448PublicKey.from_public_bytes(raw_pub)
            else:
                return False

            raw_sig = _base64.b64decode(entry.signature)
            pub.verify(raw_sig, sig_input)
            return True
        except (InvalidSignature, Exception):
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
        # Collect and concatenate duplicate DIVE-Sig headers
        dive_sig_value: str | None = None
        for k, v in resp.headers.multi_items():
            if k.lower() == "dive-sig":
                dive_sig_value = (dive_sig_value + "," + v) if dive_sig_value else v

        result.dive_sig_header = dive_sig_value
        result.report_only = report_only

        if not dive_sig_value:
            result.failure_reason = FR_MISSING_HEADERS
            result.final_decision = "allowed-report-only" if report_only else "blocked"
            self._maybe_report(result, policy)
            if not report_only:
                return result
            result.accepted = True
            result.body = body
            return result

        try:
            sig_entries = _parse_dive_sig(dive_sig_value)
        except ValueError:
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
            result.hex_digest = compute_hex_digest(body, entry.hash_algorithm)  # type: ignore[arg-type]

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
