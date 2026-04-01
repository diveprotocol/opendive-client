# DIVE Protocol Roadmap

**Version**: 1.0
**Last Updated**: March 31, 2026
**Status**: Active Development

This roadmap outlines the future development plans for the DIVE (Domain-based Integrity Verification Enforcement) protocol implementation, including compliance verification with the RFC draft and planned feature updates.

---

## Table of Contents

- [Current Status](#current-status)
- [Short-Term Goals (Q2 2026)](#short-term-goals-q2-2026)
- [Medium-Term Goals (H2 2026)](#medium-term-goals-h2-2026)
- [Long-Term Goals (2027)](#long-term-goals-2027)
- [RFC Compliance Strategy](#rfc-compliance-strategy)
- [Community Engagement](#community-engagement)
- [Dependencies](#dependencies)

---

## Current Status

**Version**: 0.1.1b2
**Features Implemented**:

- Core DIVE protocol implementation (DNS records, HTTP headers)
- Python library with CLI tools
- REST API for protection verification
- DNSSEC validation support
- Basic key management and signing

**Limitations**:

- Single scope implementation ("strict" only)
- No persistent caching
- Limited error handling for edge cases

---

## Short-Term Goals (Q2 2026)

### 1. RFC Compliance Verification (Priority)

- **Task**: Comprehensive audit of current implementation against [draft-callec-dive-00](https://datatracker.ietf.org/doc/draft-callec-dive/)
- **Deliverables**:
  - Compliance report documenting gaps
  - Test suite covering all RFC requirements
  - Updated documentation with compliance notes
- **Timeline**: April-May 2026

### 2. Core Library Improvements

- **Enhancements**:
  - Add support for custom scopes (`x-*`)
  - Implement persistent caching (Redis/SQLite)
  - Improve error handling and logging
- **Timeline**: May-June 2026

### 3. API Enhancements

- **Features**:
  - Batch checking endpoint (`/api/batch-check`)
  - Health check endpoint
  - Rate limiting improvements
- **Timeline**: June 2026

---

## Medium-Term Goals (H2 2026)

### 1. RFC Update Integration

- **Process**:
  1. Monitor IETF draft updates to [draft-callec-dive](https://datatracker.ietf.org/doc/draft-callec-dive/)
  2. Implement changes from new draft versions
  3. Maintain backward compatibility where possible
- **Deliverables**:
  - Versioned releases matching RFC draft versions
  - Migration guides for breaking changes
  - Updated test suite for new requirements
- **Timeline**: Ongoing through 2026

### 2. Expanded Ecosystem Support

- **Components**:
  - **Browser Extension**: Chrome/Firefox extension for DIVE verification
  - **Nginx Module**: Native Nginx module for DIVE header injection
  - **CDN Plugins**: Cloudflare/Akamai plugins for DIVE support
- **Timeline**: Q3-Q4 2026

### 3. Performance Optimization

- **Improvements**:
  - Parallel DNS resolution
  - Connection pooling for DNS queries
  - Optimized signature verification
- **Metrics**:
  - Reduce verification time by 40%
  - Support 1000+ requests/sec
- **Timeline**: Q4 2026

---

## Long-Term Goals (2027)

### 1. IETF Standardization Support

- **Milestones**:
  - Submit implementation report to IETF
  - Participate in interop testing events
  - Support final RFC version when published
- **Timeline**: 2027 (aligned with IETF process)

### 2. Enterprise Features

- **Features**:
  - Key rotation automation
  - Centralized policy management
  - Audit logging and compliance reporting
- **Timeline**: H1 2027

### 3. Expanded Algorithm Support

- **Algorithms**:
  - Post-quantum signature algorithms
  - Additional hash algorithms (SHA3)
- **Timeline**: H2 2027

---

## RFC Compliance Strategy

### Verification Process

1. **Structured Review**:

   - Create checklist of all RFC requirements
   - Map implementation components to requirements
   - Identify gaps and non-compliant behaviors

2. **Test Suite Development**:

   - Develop comprehensive test cases for each RFC section
   - Include positive and negative test cases
   - Automate compliance testing in CI pipeline

3. **Interoperability Testing**:
   - Test with other DIVE implementations
   - Participate in IETF interop events
   - Validate against reference implementations

### Update Process

1. **Monitoring**:

   - Subscribe to IETF draft updates
   - Participate in working group discussions
   - Track issues in GitHub linked to RFC sections

2. **Implementation**:

   - Create branches for RFC version updates
   - Maintain version compatibility matrix
   - Provide clear upgrade paths

3. **Documentation**:
   - Maintain RFC version compatibility table
   - Document breaking changes clearly
   - Provide migration guides

---

## Community Engagement

### Development Process

- **Open Development**: All work happens in public GitHub repo
- **Issue Tracking**: Use GitHub issues with RFC section labels
- **Pull Requests**: Welcome community contributions
- **Discussions**: GitHub Discussions for design topics

### Communication Channels

- **Mailing List**: dive-discuss@ietf.org
- **Chat**: #dive-protocol on Matrix
- **Meetings**: Bi-weekly community calls

### Contribution Guidelines

1. Fork the repository
2. Create feature branches (e.g., `rfc/section-3.1`)
3. Submit pull requests with:
   - Clear description of changes
   - Reference to RFC section
   - Test cases
4. Maintainers will review for RFC compliance

---

## Dependencies

### External Dependencies

| Dependency   | Purpose                    | Version |
| ------------ | -------------------------- | ------- |
| dnspython    | DNS resolution with DNSSEC | ≥2.3.0  |
| cryptography | Ed25519/Ed448 support      | ≥3.4.8  |
| httpx        | HTTP client                | ≥0.23.0 |
| Flask        | API framework              | ≥2.3.2  |

### RFC Dependencies

| RFC                  | Section           | Implementation Status     |
| -------------------- | ----------------- | ------------------------- |
| RFC 4033             | DNSSEC            | ✅ Fully implemented      |
| RFC 8032             | Ed25519/Ed448     | ✅ Fully implemented      |
| RFC 8941             | Structured Fields | ✅ Fully implemented      |
| draft-callec-dive-00 | Core Protocol     | ⚠️ Partial implementation |

---

## Release Plan

| Version | Target Date    | Focus Areas                   |
| ------- | -------------- | ----------------------------- |
| 0.2.0   | June 2026      | RFC compliance, custom scopes |
| 0.3.0   | September 2026 | Performance, ecosystem tools  |
| 0.4.0   | December 2026  | RFC updates, interop testing  |
| 1.0.0   | 2027           | IETF standardization support  |

---

## How to Help

1. **Review RFC Compliance**: Help audit the implementation against the draft
2. **Test Implementations**: Try the tools with your domains
3. **Report Issues**: File GitHub issues for any non-compliant behavior
4. **Contribute Code**: Implement missing RFC features
5. **Documentation**: Improve docs and examples

---

## License

All DIVE protocol implementations are released under the **MIT License**, making them freely available for both open-source and commercial use.
