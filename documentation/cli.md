# OpenDIVE CLI Reference

The OpenDIVE CLI provides commands to verify, download, sign, and inspect DIVE-protected resources. This document covers all available commands, options, and usage examples.

---

## Table of Contents

- [`opendive verify`](#opendive-verify)
- [`opendive download`](#opendive-download)
- [`opendive keygen`](#opendive-keygen)
- [`opendive sign`](#opendive-sign)
- [`opendive dns`](#opendive-dns)
- [`opendive version`](#opendive-version)
- [Global Options](#global-options)
- [Exit Codes](#exit-codes)
- [Examples](#examples)

---

## `opendive verify`

Verify a resource against its DIVE policy.

### Usage

```bash
opendive verify <url> [OPTIONS]
```

### Options

| Option             | Description                                                            | Default        |
| ------------------ | ---------------------------------------------------------------------- | -------------- |
| `--dns IP`         | Custom DNS resolver IP address.                                        | System default |
| `--require-dnssec` | Reject records without DNSSEC validation (recommended for production). | False          |
| `--json`           | Output the full verification result as JSON.                           | False          |

### Output

- **Human-readable**: Displays policy domain, scope, DNSSEC status, and key resolution.
- **JSON**: Structured output for scripting (see [JSON Output](#json-output)).

### Example

```bash
opendive verify https://example.com/file.tar.gz --require-dnssec
```

---

## `opendive download`

Download a resource only if DIVE verification passes.

### Usage

```bash
opendive download <url> [OPTIONS]
```

### Options

| Option                  | Description                                          | Default           |
| ----------------------- | ---------------------------------------------------- | ----------------- |
| `-o, --output FILE`     | Destination file path.                               | Filename from URL |
| `--dns IP`              | Custom DNS resolver IP address.                      | System default    |
| `--require-dnssec`      | Reject records without DNSSEC validation.            | False             |
| `--force, -f`           | Overwrite the destination file if it exists.         | False             |
| `--continue-on-no-dive` | Save the file even if the domain has no DIVE policy. | False             |

### Behavior

- The file is **only saved** if DIVE verification passes (or if no DIVE policy exists).
- If verification fails, the file is **not saved** (protects against tampered content).

### Example

```bash
opendive download https://example.com/file.tar.gz --output myfile.tar.gz --require-dnssec
```

---

## `opendive keygen`

Generate an Ed25519 or Ed448 key pair for DIVE.

### Usage

```bash
opendive keygen [OPTIONS]
```

### Options

| Option            | Description                                          | Default       |
| ----------------- | ---------------------------------------------------- | ------------- |
| `--alg ALG`       | Signature algorithm (`ed25519` or `ed448`).          | `ed25519`     |
| `--key-id ID`     | Key ID to use in the suggested DNS record.           | `key1`        |
| `--domain DOMAIN` | Domain to use in the suggested DNS record.           | `example.com` |
| `--json`          | Output as JSON (private key, public key, algorithm). | False         |

### Output

- **Private key**: Base64-encoded (keep secure!).
- **Public key**: Base64-encoded (publish in DNS).
- **Suggested DNS TXT record**: Ready-to-use format.

### Example

```bash
opendive keygen --alg ed25519 --key-id mykey --domain example.com
```

---

## `opendive sign`

Sign a file and generate a `DIVE-Sig` header entry.

### Usage

```bash
opendive sign <file> [OPTIONS]
```

### Options

| Option              | Description                                       | Default   |
| ------------------- | ------------------------------------------------- | --------- |
| `--private-key B64` | Base64-encoded private key (from `dive keygen`).  | Required  |
| `--key-id ID`       | Key ID to embed in the `DIVE-Sig` header.         | Required  |
| `--alg ALG`         | Signature algorithm (`ed25519` or `ed448`).       | `ed25519` |
| `--hash ALG`        | Hash algorithm (`sha256`, `sha384`, or `sha512`). | `sha256`  |
| `--json`            | Output as JSON.                                   | False     |

### Output

- **DIVE-Sig header entry**: Ready to add to HTTP responses.
- **Hex digest**: For verification and debugging.

### Example

```bash
opendive sign myfile.tar.gz --private-key <base64_private_key> --key-id mykey
```

---

## `opendive dns`

Inspect `_dive` and `_divekey` DNS records for a domain.

### Usage

```bash
opendive dns <fqdn> [OPTIONS]
```

### Options

| Option        | Description                                | Default        |
| ------------- | ------------------------------------------ | -------------- |
| `--dns IP`    | Custom DNS resolver IP address.            | System default |
| `--key-id ID` | Also look up this Key ID under `_divekey`. | None           |
| `--json`      | Output as JSON.                            | False          |

### Output

- **Policy record**: `_dive` configuration (scopes, directives, cache TTL).
- **Key record**: Public key, algorithm, and allowed hashes.

### Example

```bash
opendive dns example.com --key-id mykey
```

---

## Global Options

| Option      | Description                 |
| ----------- | --------------------------- |
| `--help`    | Show help message and exit. |
| `--version` | Show version and exit.      |

---

## Exit Codes

| Code | Meaning                                                       |
| ---- | ------------------------------------------------------------- |
| 0    | Success (resource accepted or command completed).             |
| 1    | Resource rejected (DIVE failure or error).                    |
| 2    | Destination file already exists (use `--force` to overwrite). |

---

## JSON Output

All commands support `--json` for machine-readable output. Example for `opendive verify`:

```json
{
  "url": "https://example.com/file.tar.gz",
  "accepted": true,
  "scope": "strict",
  "policy_domain": "example.com",
  "policy_fqdn": "example.com",
  "dnssec": true,
  "report_only": false,
  "hash_algorithm": "sha256",
  "hex_digest": "a1b2c3...",
  "signature_valid": true,
  "dive_sig_header": "key1:sha256:BASE64SIG",
  "key_resolution": [
    {
      "key_id": "key1",
      "fqdn_queried": "key1._divekey.example.com",
      "found": true,
      "dnssec_validated": true,
      "sig_algorithm": "ed25519"
    }
  ]
}
```

---

## Examples

### 1. Verify a Resource

```bash
opendive verify https://example.com/file.tar.gz --require-dnssec
```

### 2. Download a Resource (DIVE-Verified)

```bash
opendive download https://example.com/file.tar.gz --output myfile.tar.gz
```

### 3. Generate a Key Pair

```bash
opendive keygen --alg ed25519 --key-id mykey --domain example.com
```

### 4. Sign a File

```bash
opendive sign myfile.tar.gz --private-key <private_key> --key-id mykey
```

### 5. Inspect DNS Records

```bash
opendive dns example.com --key-id mykey
```

---

## Notes

- **DNSSEC**: Always use `--require-dnssec` in production.
- **Key Security**: Never expose private keys. Use HSMs or offline storage.
- **Custom Scopes**: Not supported in this release (see [Library Documentation](library.md)).
