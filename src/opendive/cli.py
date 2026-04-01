"""
cli.py - DIVE command-line interface

Commands:
  dive verify   <url>   Full client verification of a resource
  dive download <url>   Download a resource to disk (only if DIVE passes)
  dive keygen           Generate an Ed25519/Ed448 key pair
  dive sign     <file>  Sign a file and print the DIVE-Sig header entry
  dive dns      <fqdn>  Inspect _dive and _divekey DNS records
"""

from __future__ import annotations

import json
import sys
from urllib.parse import urlparse

import click

from .client import DiveClient
from .crypto import UnsupportedAlgorithm, sign_file
from .dns import (
    DiveRecordInvalid,
    DiveRecordNotFound,
    get_dive_record_walk,
    get_key_record,
)
from .keys import generate_base64_keypair

# ── Helpers ───────────────────────────────────────────────────────────────────


def _ok(msg: str) -> None:
    click.secho(f"  ✓  {msg}", fg="green")


def _fail(msg: str) -> None:
    click.secho(f"  ✗  {msg}", fg="red")


def _info(msg: str) -> None:
    click.secho(f"  ·  {msg}", fg="cyan")


def _warn(msg: str) -> None:
    click.secho(f"  !  {msg}", fg="yellow")


def _header(msg: str) -> None:
    click.secho(f"\n{msg}", bold=True)


# ── CLI root ──────────────────────────────────────────────────────────────────


@click.group()
def cli() -> None:
    """DIVE — Domain-based Integrity Verification Enforcement"""


# ── dive verify ───────────────────────────────────────────────────────────────


@cli.command("verify")
@click.argument("url")
@click.option(
    "--dns",
    "custom_dns",
    default=None,
    metavar="IP",
    help="Custom DNS resolver IP address.",
)
@click.option(
    "--require-dnssec",
    is_flag=True,
    default=False,
    help="Reject records without DNSSEC validation (recommended for production).",
)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    default=False,
    help="Output the full verification result as JSON.",
)
def cmd_verify(
    url: str, custom_dns: str | None, require_dnssec: bool, output_json: bool
) -> None:
    """
    Download and DIVE-verify a resource at URL.

    Exit codes:
      0  resource accepted
      1  resource rejected (or DIVE not supported / error)
    """
    _header(f"DIVE verify: {url}")

    with DiveClient(custom_dns=custom_dns, require_dnssec=require_dnssec) as client:
        result = client.verify(url)

    if output_json:
        # Rebuild a serialisable summary
        summary = {
            "url": result.url,
            "accepted": result.accepted,
            "scope": result.scope,
            "policy_domain": result.policy_domain,
            "policy_fqdn": result.policy_fqdn,
            "dnssec": result.dnssec_validated,
            "report_only": result.report_only,
            "failure_reason": result.failure_reason,
            "final_decision": result.final_decision,
            "hash_algorithm": result.hash_algorithm,
            "hex_digest": result.hex_digest,
            "signature_valid": result.signature_valid,
            "dive_sig_header": result.dive_sig_header,
            "key_resolution": [
                {
                    "key_id": e.key_id,
                    "fqdn_queried": e.fqdn_queried,
                    "found": e.found,
                    "dnssec_validated": e.dnssec_validated,
                    "sig_algorithm": e.sig_algorithm,
                }
                for e in result.key_resolution
            ],
        }
        click.echo(json.dumps(summary, indent=2))
        sys.exit(0 if result.accepted else 1)

    # Human-readable output
    if result.policy_domain:
        _info(f"Policy domain  : {result.policy_domain}")
    if result.policy_fqdn:
        _info(f"Resource FQDN  : {result.policy_fqdn}")
    if result.dnssec_validated:
        _ok("DNSSEC validated")
    else:
        _warn("DNSSEC not validated")

    if result.scope:
        _info(f"Scope matched  : {result.scope}")
    else:
        _info("Not in any DIVE scope — accepted without verification")

    if result.dive_sig_header:
        _info(f"DIVE-Sig       : {result.dive_sig_header}")

    if result.hash_algorithm and result.hex_digest:
        _info(f"Hash ({result.hash_algorithm}): {result.hex_digest}")

    for entry in result.key_resolution:
        prefix = "✓" if entry.found else "✗"
        click.secho(
            f"  {prefix}  Key {entry.key_id!r} @ {entry.fqdn_queried}  "
            f"{'(DNSSEC)' if entry.dnssec_validated else ''}",
            fg="green" if entry.found else "red",
        )

    click.echo()
    if result.accepted:
        if result.report_only and result.failure_reason:
            _warn(f"Accepted (report-only mode) — reason: {result.failure_reason}")
        else:
            _ok("Resource ACCEPTED")
        sys.exit(0)
    else:
        _fail(f"Resource REJECTED — {result.failure_reason}")
        sys.exit(1)


# ── dive keygen ───────────────────────────────────────────────────────────────


@cli.command("keygen")
@click.option(
    "--alg",
    default="ed25519",
    type=click.Choice(["ed25519", "ed448"], case_sensitive=False),
    show_default=True,
    help="Signature algorithm.",
)
@click.option(
    "--key-id",
    default="key1",
    show_default=True,
    help="Key ID to use in the suggested DNS record.",
)
@click.option(
    "--domain",
    default="example.com",
    show_default=True,
    help="Domain to use in the suggested DNS record.",
)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    default=False,
    help="Output as JSON (private_key, public_key, algorithm).",
)
def cmd_keygen(alg: str, key_id: str, domain: str, output_json: bool) -> None:
    """Generate an Ed25519 or Ed448 key pair for DIVE."""
    pair = generate_base64_keypair(alg)

    if output_json:
        click.echo(json.dumps(pair, indent=2))
        return

    _header("Generated DIVE key pair")
    _info(f"Algorithm   : {pair['algorithm']}")
    click.echo()
    click.secho("  Private key (keep secret — use for signing):", bold=True)
    click.echo(f"  {pair['private_key']}")
    click.echo()
    click.secho("  Public key (publish in DNS key record):", bold=True)
    click.echo(f"  {pair['public_key']}")
    click.echo()
    click.secho("  Suggested DNS TXT record:", bold=True)
    click.echo(
        f"  {key_id}._divekey.{domain}.  900  IN  TXT  "
        f'"sig=\\"{alg}\\", key=:{pair["public_key"]}:, allowed-hash=(\\"sha256\\" \\"sha384\\"), cache=900"',
    )
    click.echo()
    _warn("Store the private key securely. Never commit it to version control.")


# ── dive sign ─────────────────────────────────────────────────────────────────


@cli.command("sign")
@click.argument("file", type=click.Path(exists=True, readable=True))
@click.option(
    "--private-key",
    required=True,
    metavar="B64",
    help="Base64-encoded private key (from `dive keygen`).",
)
@click.option(
    "--key-id",
    required=True,
    metavar="ID",
    help="Key ID to embed in the DIVE-Sig header.",
)
@click.option(
    "--alg",
    default="ed25519",
    type=click.Choice(["ed25519", "ed448"], case_sensitive=False),
    show_default=True,
    help="Signature algorithm.",
)
@click.option(
    "--hash",
    "hash_alg",
    default="sha256",
    type=click.Choice(
        ["sha256", "sha384", "sha512", "sha3-256", "sha3-384", "sha3-512"],
        case_sensitive=False,
    ),
    show_default=True,
    help="Hash algorithm.",
)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    default=False,
    help="Output as JSON.",
)
def cmd_sign(
    file: str,
    private_key: str,
    key_id: str,
    alg: str,
    hash_alg: str,
    output_json: bool,
) -> None:
    """
    Sign FILE and print the DIVE-Sig header value.

    The output can be added directly as an HTTP response header on your server.
    """
    with open(file, "rb") as fh:
        data = fh.read()

    try:
        result = sign_file(
            data,
            private_key,
            sig_algorithm=alg,  # type: ignore[arg-type]
            hash_algorithm=hash_alg,  # type: ignore[arg-type]
        )
    except UnsupportedAlgorithm as exc:
        click.secho(f"Error: {exc}", fg="red", err=True)
        sys.exit(1)
    except Exception as exc:
        click.secho(f"Error signing file: {exc}", fg="red", err=True)
        sys.exit(1)

    dive_sig_entry = f"{key_id}:{result['hash_algorithm']}:{result['signature']}"

    if output_json:
        click.echo(
            json.dumps(
                {
                    "key_id": key_id,
                    "hash_algorithm": result["hash_algorithm"],
                    "sig_algorithm": result["sig_algorithm"],
                    "hex_digest": result["hex_digest"],
                    "signature": result["signature"],
                    "dive_sig_entry": dive_sig_entry,
                },
                indent=2,
            )
        )
        return

    _header(f"DIVE signature for: {file}")
    _info(f"Hash algorithm : {result['hash_algorithm']}")
    _info(f"Sig  algorithm : {result['sig_algorithm']}")
    _info(f"Hex digest     : {result['hex_digest']}")
    click.echo()
    click.secho("  DIVE-Sig header entry:", bold=True)
    click.echo(f"  {dive_sig_entry}")
    click.echo()
    click.secho("  Full HTTP response header:", bold=True)
    click.echo(f"  DIVE-Sig: {dive_sig_entry}")


# ── dive download ─────────────────────────────────────────────────────────────


@cli.command("download")
@click.argument("url")
@click.option(
    "-o",
    "--output",
    default=None,
    metavar="FILE",
    help=(
        "Destination file path. "
        "Defaults to the filename from the URL, or 'index' if none can be inferred."
    ),
)
@click.option(
    "--dns",
    "custom_dns",
    default=None,
    metavar="IP",
    help="Custom DNS resolver IP address.",
)
@click.option(
    "--require-dnssec",
    is_flag=True,
    default=False,
    help="Reject records without DNSSEC validation.",
)
@click.option(
    "--force",
    "-f",
    is_flag=True,
    default=False,
    help="Overwrite the destination file if it already exists.",
)
@click.option(
    "--continue-on-no-dive",
    is_flag=True,
    default=False,
    help=(
        "Save the file even when the domain publishes no DIVE policy. "
        "By default the file is saved (DIVE is opt-in), but this flag "
        "makes that behaviour explicit and suppresses the warning."
    ),
)
def cmd_download(
    url: str,
    output: str | None,
    custom_dns: str | None,
    require_dnssec: bool,
    force: bool,
    continue_on_no_dive: bool,
) -> None:
    """
    Download URL to disk — like wget, but DIVE-aware.

    The file is written only when DIVE verification passes (or when the
    domain does not publish a DIVE policy at all, in which case the
    resource is accepted per the RFC).

    If verification fails the download is aborted and the file is NOT
    written, protecting the user from tampered content.

    Exit codes:
      0  file saved successfully
      1  DIVE verification failed (file not saved)
      2  destination file already exists (use --force to overwrite)
    """
    from pathlib import Path
    from urllib.parse import unquote, urlparse

    # ── Determine output path ─────────────────────────────────────────────────
    if output:
        dest = Path(output)
    else:
        parsed = urlparse(url)
        filename = unquote(parsed.path.rstrip("/").rsplit("/", 1)[-1]) or "index"
        dest = Path(filename)

    if dest.exists() and not force:
        click.secho(
            f"  ✗  Destination already exists: {dest}\n"
            f"     Use --force / -f to overwrite.",
            fg="red",
            err=True,
        )
        sys.exit(2)

    # ── Run DIVE verification ─────────────────────────────────────────────────
    _header(f"DIVE download: {url}")
    _info(f"Destination    : {dest}")

    with DiveClient(custom_dns=custom_dns, require_dnssec=require_dnssec) as client:
        result = client.verify(url)

    # ── Report what happened ──────────────────────────────────────────────────
    if result.policy_domain:
        _info(f"Policy domain  : {result.policy_domain}")
        _info(f"DNSSEC         : {'yes' if result.dnssec_validated else 'no'}")
    elif not continue_on_no_dive:
        _warn(
            "No DIVE policy found for this domain — downloading anyway (DIVE is opt-in)."
        )

    if result.scope:
        _info(f"Scope matched  : {result.scope}")

    if result.hash_algorithm and result.hex_digest:
        _info(f"Hash ({result.hash_algorithm}): {result.hex_digest}")

    for entry in result.key_resolution:
        icon = "✓" if entry.found else "✗"
        click.secho(
            f"  {icon}  Key {entry.key_id!r} @ {entry.fqdn_queried}"
            + (" (DNSSEC)" if entry.dnssec_validated else ""),
            fg="green" if entry.found else "red",
        )

    click.echo()

    if not result.accepted:
        _fail(
            f"Verification FAILED — {result.failure_reason}\n"
            f"     File NOT saved to protect against tampered content.",
        )
        sys.exit(1)

    # ── Write file ────────────────────────────────────────────────────────────
    if result.body is None:
        # Should not happen when accepted=True, but guard defensively
        _fail("No response body available. File not saved.")
        sys.exit(1)

    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(result.body)

    size_kb = len(result.body) / 1024
    if result.report_only and result.failure_reason:
        _warn(
            f"Saved {dest}  ({size_kb:.1f} KB) "
            f"— report-only mode, failure: {result.failure_reason}",
        )
    else:
        _ok(
            f"Saved {dest}  ({size_kb:.1f} KB)"
            + (
                " — DIVE verified ✓" if result.scope else " — no DIVE policy (accepted)"
            ),
        )


# ── dive dns ──────────────────────────────────────────────────────────────────


@cli.command("dns")
@click.argument("fqdn_or_url")
@click.option(
    "--dns",
    "custom_dns",
    default=None,
    metavar="IP",
    help="Custom DNS resolver IP.",
)
@click.option(
    "--key-id",
    default=None,
    metavar="ID",
    help="Also look up this Key ID under _divekey.",
)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    default=False,
    help="Output as JSON.",
)
def cmd_dns(
    fqdn_or_url: str, custom_dns: str | None, key_id: str | None, output_json: bool
) -> None:
    """
    Inspect _dive and (optionally) _divekey DNS records for FQDN or URL.
    """
    # Extract domain from URL if needed
    parsed = urlparse(fqdn_or_url)
    fqdn = parsed.netloc if parsed.netloc else fqdn_or_url

    # Rest of the function remains the same
    output: dict = {"fqdn": fqdn, "policy": None, "key": None}

    # Policy record
    try:
        records = get_dive_record_walk(fqdn, custom_dns)
        policy = records[0] if records else None
    except DiveRecordNotFound:
        policy = None
    except DiveRecordInvalid as exc:
        policy = {"_error": str(exc)}

    output["policy"] = policy

    # Key record
    if key_id:
        try:
            key_records = get_key_record(fqdn, key_id, custom_dns)
            output["key"] = key_records[0] if key_records else None
        except DiveRecordNotFound:
            output["key"] = None
        except DiveRecordInvalid as exc:
            output["key"] = {"_error": str(exc)}

    if output_json:

        def _clean(d):
            if isinstance(d, dict):
                return {k: _clean(v) for k, v in d.items()}
            if isinstance(d, list):
                return [_clean(i) for i in d]
            return d

        click.echo(json.dumps(_clean(output), indent=2))
        return

    _header(f"DIVE DNS inspection: {fqdn}")

    if policy:
        if "_error" in policy:
            _fail(f"Policy record invalid: {policy['_error']}")
        else:
            _ok(f"Policy record found at {policy.get('_fqdn')}")
            _info(f"  Version    : {policy.get('v')}")
            _info(f"  Scopes     : {policy.get('scopes', [])}")
            _info(f"  Directives : {policy.get('directives', [])}")
            _info(f"  Cache TTL  : {policy.get('cache', 0)}s")
            _info(f"  DNSSEC     : {policy.get('_dnssec_validated', False)}")
            if policy.get("report-to"):
                _info(f"  Report-to  : {policy['report-to']}")
    else:
        _warn("No _dive policy record found (DIVE not supported for this domain).")

    if key_id:
        click.echo()
        key = output.get("key")
        if key:
            if "_error" in key:
                _fail(f"Key record invalid: {key['_error']}")
            else:
                _ok(f"Key record found at {key.get('_fqdn')}")
                _info(f"  Key ID       : {key.get('_key_id')}")
                _info(f"  Algorithm    : {key.get('sig')}")
                _info(f"  Public key   : {key.get('key', '')}")
                _info(f"  Allowed hash : {key.get('allowed-hash', 'any')}")
                _info(f"  Cache TTL    : {key.get('cache', 0)}s")
                _info(f"  DNSSEC       : {key.get('_dnssec_validated', False)}")
        else:
            _warn(f"No _divekey record found for key ID {key_id!r} at {fqdn}.")


# ── dive version ──────────────────────────────────────────────────────────────


@cli.command("version")
def cmd_version() -> None:
    """Display version and project information."""
    _header("DIVE — Version and Project Information")
    _info(f"Version:        0.1.1b2 (0.1.1-beta.2+draft.00)")
    _info(f"License:        MIT")
    _info(f"Project repo:   https://github.com/diveprotocol/opendive-client")
    _info(f"Project site:   https://diveprotocol.org")
    _info(f"Author:         Matéo Florian Callec <mateo@callec.net>")


# ── Entry point ───────────────────────────────────────────────────────────────


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
