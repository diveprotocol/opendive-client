"""
dns.py - DIVE DNS Resolution

This module handles DNS record resolution for the DIVE protocol with full
DNSSEC validation support. It implements domain walking for policy and key
records while ensuring cryptographic validation of DNS responses.

Key improvements:
- Uses system default DNS resolvers by default
- Properly configures EDNS with DO flag for DNSSEC validation
- Maintains backward compatibility with custom DNS resolvers
"""

import logging
import re
from typing import Any

import dns.dnssec
import dns.flags
import dns.resolver

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Protocol Constants
DIVE_PREFIX = "_dive"
DIVE_KEY_PREFIX = "_divekey"

# Supported algorithms
ALLOWED_ALGORITHMS = {"ed25519", "ed448"}
ALLOWED_HASH = {"sha256", "sha384", "sha512", "sha3-256", "sha3-384", "sha3-512"}

# Required fields for records
DIVE_REQUIRED_FIELDS = {"v", "scopes"}
DIVEKEY_REQUIRED_FIELDS = {"sig", "key"}


class DiveRecordNotFound(Exception):
    """Raised when no DIVE record is found for a domain"""


class DiveRecordInvalid(Exception):
    """Raised when a DIVE record is malformed or fails validation"""


def _make_resolver(custom_dns: str | None = None) -> dns.resolver.Resolver:
    """
    Create a DNS resolver configured for DNSSEC validation.

    Uses system default resolvers unless custom_dns is specified.
    Configures EDNS with DO flag for proper DNSSEC validation.

    Args:
        custom_dns: Optional custom DNS resolver IP address

    Returns:
        Configured DNS resolver with DNSSEC validation enabled
    """
    resolver = dns.resolver.Resolver()

    # Use system default resolvers unless custom_dns is provided
    if custom_dns:
        resolver.nameservers = [custom_dns]

    resolver.use_edns(0, dns.flags.DO, 1232)

    # Set reasonable timeouts
    resolver.timeout = 5
    resolver.lifetime = 5

    return resolver


def _query_txt(fqdn: str, custom_dns: str | None = None) -> list[dict[str, Any]]:
    """
    Query TXT records with DNSSEC validation.

    Uses EDNS DO flag for DNSSEC validation and checks AD flag in response.

    Args:
        fqdn: Fully Qualified Domain Name to query
        custom_dns: Optional custom DNS resolver

    Returns:
        List of records with raw content and validation status

    Raises:
        DiveRecordInvalid: If DNSSEC validation fails
    """
    resolver = _make_resolver(custom_dns)

    try:
        logger.debug(f"Resolving TXT record for {fqdn} with DNSSEC validation")
        answers = resolver.resolve(fqdn, "TXT")

        # Check AD flag in response to verify DNSSEC validation
        dnssec_validated = bool(answers.response.flags & dns.flags.AD)

        # Process valid records
        results = []
        for rdata in answers:
            full = b"".join(rdata.strings).decode("utf-8")
            results.append(
                {
                    "raw": full,
                    "_dnssec_validated": dnssec_validated,
                    "_fqdn": fqdn,
                }
            )
        return results

    except dns.resolver.NXDOMAIN:
        logger.debug(f"No record found for {fqdn} (NXDOMAIN)")
        return []
    except dns.resolver.NoAnswer:
        logger.debug(f"No TXT records found for {fqdn}")
        return []
    except dns.dnssec.ValidationFailure as e:
        logger.error(f"DNSSEC validation failed for {fqdn}: {e!s}")
        raise DiveRecordInvalid(f"DNSSEC validation failed: {e!s}")
    except Exception as e:
        logger.error(f"DNS query failed for {fqdn}: {e!s}")
        raise DiveRecordInvalid(f"DNS query failed: {e!s}")


def _parse_txt_fields(raw: str) -> dict[str, Any]:
    """
    Parse structured field values from TXT records.

    Supports various value formats including:
    - key=value
    - key="quoted value"
    - key=(list "of" "values")
    - key=:base64:

    Args:
        raw: Raw TXT record content

    Returns:
        Parsed dictionary of key-value pairs
    """
    params = {}
    pattern = re.compile(
        r"(\w[\w-]*)\s*=\s*"  # key=
        r"("
        r":\S+?:"  # :base64:
        r'|"[^"]*"'  # "quoted"
        r"|\([^)]*\)"  # (list)
        r"|[^,\s]+"  # bare value
        r")",
    )

    for match in pattern.finditer(raw):
        key = match.group(1).strip().lower()
        value = match.group(2).strip()

        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        elif value.startswith("(") and value.endswith(")"):
            inner = value[1:-1]
            items = re.findall(r'"([^"]+)"', inner)
            value = items
        elif value.startswith(":") and value.endswith(":"):
            value = value[1:-1]

        params[key] = value
    return params


def _parse_dive_record(raw: str) -> dict[str, Any]:
    """
    Parse and validate a _dive policy record.

    Validates required fields and protocol version.

    Args:
        raw: Raw TXT record content

    Returns:
        Validated policy record

    Raises:
        DiveRecordInvalid: If record is invalid
    """
    params = _parse_txt_fields(raw)

    for field in DIVE_REQUIRED_FIELDS:
        if field not in params:
            raise DiveRecordInvalid(f"Missing required field: {field!r}")

    if params.get("v") != "dive-draft-00":
        raise DiveRecordInvalid(f"Unsupported version: {params.get('v')!r}")

    return params


def _parse_divekey_record(raw: str) -> dict[str, Any]:
    """
    Parse and validate a _divekey record.

    Validates required fields, algorithms, and hashes.

    Args:
        raw: Raw TXT record content

    Returns:
        Validated key record

    Raises:
        DiveRecordInvalid: If record is invalid
    """
    params = _parse_txt_fields(raw)

    for field in DIVEKEY_REQUIRED_FIELDS:
        if field not in params:
            raise DiveRecordInvalid(f"Missing required field: {field!r}")

    sig_val = params["sig"].lower()
    if sig_val not in ALLOWED_ALGORITHMS:
        raise DiveRecordInvalid(
            f"Unsupported algorithm {sig_val!r}, allowed: {ALLOWED_ALGORITHMS}",
        )
    params["sig"] = sig_val

    if "allowed-hash" in params:
        hashes = (
            params["allowed-hash"]
            if isinstance(params["allowed-hash"], list)
            else [params["allowed-hash"]]
        )
        for h in hashes:
            if h not in ALLOWED_HASH:
                raise DiveRecordInvalid(
                    f"Unsupported hash {h!r}, allowed: {ALLOWED_HASH}"
                )
        params["allowed-hash"] = hashes

    return params


def _domain_walk(fqdn: str) -> list[str]:
    """
    Generate domain hierarchy from FQDN to apex.

    Args:
        fqdn: Fully Qualified Domain Name

    Returns:
        List of domains from specific to general
    """
    parts = fqdn.rstrip(".").split(".")
    return [".".join(parts[i:]) for i in range(len(parts) - 1)]


def get_dive_record(fqdn: str, custom_dns: str | None = None) -> list[dict[str, Any]]:
    """
    Retrieve _dive policy record with DNSSEC validation.

    Args:
        fqdn: Domain to query
        custom_dns: Optional custom DNS resolver

    Returns:
        List of validated policy records

    Raises:
        DiveRecordNotFound: If no record found
        DiveRecordInvalid: If validation fails
    """
    target = f"{DIVE_PREFIX}.{fqdn}"
    try:
        records = _query_txt(target, custom_dns)
        if not records:
            raise DiveRecordNotFound(f"No _dive record found at {target!r}")

        parsed_records = []
        for record in records:
            try:
                parsed = _parse_dive_record(record["raw"])
                parsed["_dnssec_validated"] = record["_dnssec_validated"]
                parsed["_fqdn"] = record["_fqdn"]
                parsed_records.append(parsed)
            except DiveRecordInvalid as e:
                logger.warning(f"Invalid _dive record at {target}: {e!s}")
                continue

        return parsed_records

    except DiveRecordInvalid as e:
        logger.error(f"Failed to retrieve _dive record for {target}: {e!s}")
        raise


def get_dive_record_walk(
    fqdn: str, custom_dns: str | None = None
) -> list[dict[str, Any]]:
    """
    Retrieve _dive policy record walking up domain hierarchy.

    Args:
        fqdn: Domain to query
        custom_dns: Optional custom DNS resolver

    Returns:
        List of validated policy records

    Raises:
        DiveRecordNotFound: If no record found in hierarchy
    """
    for domain in _domain_walk(fqdn):
        try:
            return get_dive_record(domain, custom_dns)
        except DiveRecordNotFound:
            continue

    raise DiveRecordNotFound(f"No _dive record found walking from {fqdn!r} to apex")


def get_key_record(
    fqdn: str, key_id: str, custom_dns: str | None = None
) -> list[dict[str, Any]]:
    """
    Retrieve _divekey record with DNSSEC validation.

    Args:
        fqdn: Domain to query
        key_id: Key identifier
        custom_dns: Optional custom DNS resolver

    Returns:
        List of validated key records

    Raises:
        DiveRecordNotFound: If no record found
        DiveRecordInvalid: If validation fails
    """
    target = f"{key_id}.{DIVE_KEY_PREFIX}.{fqdn}"
    try:
        records = _query_txt(target, custom_dns)
        if not records:
            raise DiveRecordNotFound(f"No _divekey record found at {target!r}")

        keys = []
        for record in records:
            try:
                parsed = _parse_divekey_record(record["raw"])
                parsed["_dnssec_validated"] = record["_dnssec_validated"]
                parsed["_fqdn"] = record["_fqdn"]
                parsed["_key_id"] = key_id
                keys.append(parsed)
            except DiveRecordInvalid as e:
                logger.warning(f"Invalid _divekey record at {target}: {e!s}")
                continue

        return keys

    except DiveRecordInvalid as e:
        logger.error(f"Failed to retrieve _divekey record for {target}: {e!s}")
        raise


def get_key_record_walk(
    fqdn: str, key_id: str, custom_dns: str | None = None
) -> list[dict[str, Any]]:
    """
    Retrieve _divekey record walking up domain hierarchy.

    Args:
        fqdn: Domain to query
        key_id: Key identifier
        custom_dns: Optional custom DNS resolver

    Returns:
        List of validated key records

    Raises:
        DiveRecordNotFound: If no record found in hierarchy
    """
    for domain in _domain_walk(fqdn):
        try:
            return get_key_record(domain, key_id, custom_dns)
        except DiveRecordNotFound:
            continue

    raise DiveRecordNotFound(
        f"No _divekey/{key_id!r} record found walking from {fqdn!r} to apex"
    )
