# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in OpenDIVE, please report it responsibly:

1. **Do not open a public issue** on GitHub.
2. **Email**: Send a detailed report to [mateo@callec.net](mailto:mateo@callec.net).
3. **Encryption**: For sensitive information, use PGP (Key ID: `TODO`).
4. **Response**: You will receive an acknowledgment within 48 hours, and a patch or mitigation plan within 7 days.

---

## Supported Versions

Only the latest alpha release (`0.1.0-alpha.2+draft.00`) is currently supported. Security updates will be provided for all future stable releases (`>=1.0.0`).

| Version                | Supported          |
| ---------------------- | ------------------ |
| 0.1.0-alpha.2+draft.00 | :white_check_mark: |
| 0.1.0-alpha.1+draft.00 | :x:                |
| <0.1.0                 | :x:                |

---

## Security Features

### DNSSEC Validation

- OpenDIVE **requires DNSSEC** for all DIVE records (`_dive`, `_divekey`).
- Without DNSSEC, records are treated as invalid (configurable via `--require-dnssec`).

### Cryptographic Algorithms

- **Signatures**: Only Ed25519 and Ed448 are supported (RFC 8032).
- **Hashes**: Only SHA-256, SHA-384, and SHA-512 are allowed.
- Weak algorithms (RSA, ECDSA, SHA-1, MD5) are explicitly rejected.

### Key Management

- Private keys **must** be stored securely (e.g., HSM, offline).
- Never commit private keys to version control.
- Key rotation is recommended (see [RFC §7.1](https://datatracker.ietf.org/doc/draft-callec-dive/#name-key-rotation)).

### Failure Reporting

- Reports are sent **only over HTTPS** to the `report-to` endpoint.
- Reports include minimal metadata (URL, hash, failure reason).

---

## Best Practices for Users

1. **Enable DNSSEC Validation**:
   Always use `--require-dnssec` in production.

   ```bash
   dive verify --require-dnssec https://example.com/file
   ```

2. **Monitor Key Rotation**:
   Use `dive dns` to inspect key records and ensure they are up-to-date.

   ```bash
   dive dns example.com --key-id mykey
   ```

3. **Use HTTPS**:
   OpenDIVE enforces HTTPS if the `https-required` directive is set.

4. **Audit Dependencies**:
   Regularly update `dnspython` and `cryptography` to patch vulnerabilities.

---

## Security Audits

- No formal audit has been conducted yet.
- Contributions to improve security are welcome!

---

## Credits

- **Author**: Matéo Florian CALLEC
- **License**: MIT
