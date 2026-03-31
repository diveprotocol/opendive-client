# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
