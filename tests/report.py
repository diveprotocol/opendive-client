#!/usr/bin/env python3
"""
DIVE Reporting Endpoint Tester

This script sends a sample DIVE report to a specified reporting endpoint
and evaluates the HTTP response.

Based on the full reference template aligned with the PHP implementation.
"""

import argparse
import json
import sys
import time

import requests

# Full report template aligned with the specification
SAMPLE_REPORT = {
    "report-version": "0.1",
    "timestamp": None,  # Will be replaced with Unix timestamp
    "client": {"user-agent": "DIVE-Tester/1.0"},
    "policy": {
        "domain": "example.com",
        "fqdn": "download.example.com",
        "dnssec-validated": True,
    },
    "resource": {
        "url": "https://download.example.com/files/test.txt",
        "method": "GET",
        "status-code": 200,
        "scope": "strict",
    },
    "headers-received": {
        "signature-input": 'sigkey1=("content-digest");keyid="key1";alg="ed25519"',
        "content-digest": "sha-256=:MEUCIQD...BASE64DIGEST...:",
    },
    "key-resolution": [
        {
            "key-id": "key1",
            "fqdn-queried": "key1._divekey.download.example.com",
            "found": True,
            "dnssec-validated": True,
            "sig-algorithm": "ed25519",
        }
    ],
    "validation": {
        "hash-algorithm": "sha256",
        "hash-computed": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "signature-valid": False,
        "failure-reason": "signature-mismatch",
        "final-decision": "blocked",
    },
}


def send_dive_report(report_url: str, verbose: bool = False) -> dict:
    """
    Send a DIVE report to the specified endpoint.

    Args:
        report_url: Target reporting endpoint URL
        verbose: Enable detailed output

    Returns:
        Dictionary containing request/response details
    """
    report = SAMPLE_REPORT.copy()
    report["timestamp"] = int(time.time())

    if verbose:
        print(f"Sending report to: {report_url}")
        print("Report payload:")
        print(json.dumps(report, indent=2))

    try:
        headers = {"Content-Type": "application/json", "User-Agent": "DIVE-Tester/1.0"}

        response = requests.post(
            report_url, data=json.dumps(report), headers=headers, timeout=10
        )

        return {
            "success": response.status_code in (200, 202, 204),
            "status_code": response.status_code,
            "response_headers": dict(response.headers),
            "response_text": response.text,
            "report_sent": report,
        }

    except requests.exceptions.RequestException as exc:
        return {
            "success": False,
            "error": str(exc),
            "report_sent": report if verbose else None,
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="Test a DIVE reporting endpoint")
    parser.add_argument("url", help="DIVE reporting endpoint URL")
    parser.add_argument("--verbose", action="store_true", help="Enable detailed output")

    args = parser.parse_args()

    results = send_dive_report(args.url, args.verbose)

    print("\n=== DIVE Endpoint Test Results ===")
    print(f"Endpoint: {args.url}")

    if "error" in results:
        print(f"\nTest failed: {results['error']}")
        sys.exit(1)

    status_label = "SUCCESS" if results["success"] else "FAILURE"
    print(f"\nStatus: {status_label}")
    print(f"HTTP Status Code: {results['status_code']}")

    if not results["success"]:
        print("\nResponse details:")
        print(f"Headers: {results['response_headers']}")
        print(f"Body: {results['response_text']}")
    elif args.verbose:
        print("\nReport successfully received by the server")


if __name__ == "__main__":
    main()
