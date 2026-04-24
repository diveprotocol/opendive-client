# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.0-beta.1+draft.01] — 2026-04-24

- N/A

---

## [0.2.0-beta.1+draft.01] — 2026-04-24

### Changed

* **User-Agent**: Updated the User-Agent string to `OpenDIVE-Client/0.2`.

---

## [0.2.0-alpha.1+draft.01] — 2026-04-19

### Changed

- **Protocol version**: DNS `_dive` policy records now require `v="dive-draft-01"` (previously `dive-draft-00`).
- **Signature headers**: Replaced the custom `DIVE-Sig` header with RFC 9421 HTTP Message Signatures.
  - Servers must now send three standard headers: `Content-Digest` (RFC 9530), `Signature-Input`, and `Signature`.
  - `Content-Digest` carries the base64-encoded body hash (e.g. `sha-256=:BASE64:`).
  - `Signature-Input` declares the signature label, covered components (`"content-digest"`), `keyid`, and `alg`.
  - `Signature` carries the base64-encoded signature value per RFC 9421.
- **Signature input construction**: Signatures are now computed over the RFC 9421 signature base (derived from `Signature-Input` covered components), replacing the custom `algorithm:raw_hash_bytes` input.
- **Multiple signatures**: Expressed as multiple labeled entries in the same `Signature-Input` / `Signature` headers (RFC 9421 §4.2) rather than comma-separated `DIVE-Sig` entries.
- **Failure reports**: `headers-received.dive-sig` replaced by `headers-received.signature-input` and `headers-received.content-digest`.
- **`dive sign` CLI**: Now outputs `Content-Digest`, `Signature-Input`, and `Signature` headers instead of a single `DIVE-Sig` header.
- **`sign_file()` API**: Now requires a `key_id` argument; returns `content_digest_header`, `signature_input_header`, and `signature_header` fields.
- **`sign_hash()` / `verify_hash()` API**: Added optional `key_id` parameter (default `"key1"`); both now operate over the RFC 9421 signature base.

---

## [0.1.1] - 2026-04-01

### Added

- **SHA3 Support**: Added implementations for SHA3-256, SHA3-384, and SHA3-512 hash algorithms.

### Changed

- Removal of beta version tags and draft metadata for the production version.

### Fixed

- **Hash Verification**: Corrected the implementation of hash verification, which was previously flawed.

### Security

- N/A

### Known Issues

- N/A

---

## [0.1.1-beta.2+draft.00] - 2026-04-01

### Added

- **SHA3 Support**: Added implementations for SHA3-256, SHA3-384, and SHA3-512 hash algorithms.

### Changed

- N/A

### Fixed

- **Hash Verification**: Corrected the implementation of hash verification, which was previously flawed.

### Security

- N/A

### Known Issues

- N/A

---

## [0.1.1-beta.1+draft.00] - 2026-04-01

### Added

- URL support in the `dive dns` command:

  - The command now accepts full URLs in addition to domain names.
  - Automatically extracts the domain for DNS resolution.

### Changed

- N/A

### Fixed

- N/A

### Security

- N/A

### Known Issues

- N/A

---

## [0.1.1-alpha.1+draft.00] - 2026-04-01

### Added

- Clarified signature pipeline behavior in documentation.
- Improved internal consistency between hashing and signing steps.

### Changed

- Refactored `sign_hash` implementation:

  - The signature is now generated from the canonical payload returned by `build_signature_input(...)` instead of the UTF-8 encoded digest string.
  - Aligns signing logic with protocol expectations and verification flow.

### Fixed

- Fixed critical signature mismatch issue:

  - Previously, the digest (`hex string`) was encoded and signed directly.
  - This caused incompatibility with verification logic expecting a structured payload.
  - The new implementation ensures both signer and verifier operate on the same canonical input.

### Security

- Eliminates ambiguity in signed data representation, reducing risk of signature misuse or verification inconsistencies.

### Known Issues

- Existing signatures generated with previous versions are not compatible with this version.

---

## [0.1.0+draft.00] - 2026-03-31

### Added

- Updated package metadata in `pyproject.toml` to ensure correct deployment.
- Additional package information added for clarity and completeness.

### Changed

- N/A (initial draft for deployment adjustments).

### Fixed

- N/A

### Security

- N/A

### Known Issues

- N/A

---

## [0.1.0-alpha.2+draft.00] - 2026-03-31

### Added

- Initial alpha release of OpenDIVE.
- Core DIVE client implementation:
  - DNSSEC-backed policy and key resolution.
  - HTTP header parsing and signature verification.
  - Support for Ed25519/Ed448 and SHA-256/384/512.
- CLI commands:
  - `dive verify`: Verify a resource.
  - `dive download`: Download a resource only if DIVE verification passes.
  - `dive keygen`: Generate Ed25519/Ed448 key pairs.
  - `dive sign`: Sign a file and generate a `DIVE-Sig` header.
  - `dive dns`: Inspect DIVE DNS records.
- Basic caching for DNS records.
- JSON output for all commands.
- Failure reporting (RFC-compliant).

### Changed

- N/A (First release).

### Fixed

- N/A (First release).

### Security

- DNSSEC validation is optional (for testing) but recommended for production.
- Private keys are never logged or exposed in CLI output.

### Known Issues

- No support for custom scopes (`x-*`) in this release.
- Limited error handling for malformed DNS records.
- No persistent cache (in-memory only).

---

## [Unreleased]

### Planned

- Persistent cache (SQLite/Redis).
- Support for custom scopes.
- Improved documentation and examples.
- CI/CD pipeline for automated testing.
