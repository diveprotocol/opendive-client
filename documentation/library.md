# OpenDIVE Library Reference

OpenDIVE provides a Python library for integrating DIVE verification into applications. This document covers all classes, methods, and advanced usage patterns.

---

## Table of Contents

- [Installation](#installation)
- [Core Classes](#core-classes)
  - [`DiveClient`](#diveclient)
  - [`VerificationResult`](#verificationresult)
- [DNS Resolution](#dns-resolution)
- [Cryptographic Operations](#cryptographic-operations)
- [Key Management](#key-management)
- [Error Handling](#error-handling)
- [Advanced Usage](#advanced-usage)
  - [Custom DNS Resolvers](#custom-dns-resolvers)
  - [Caching](#caching)
  - [Parallel Verification](#parallel-verification)
- [Examples](#examples)

---

## Installation

```bash
pip install opendive-client
```

---

## Core Classes

### `DiveClient`

The main class for DIVE verification.

#### Constructor

```python
from dive.client import DiveClient

client = DiveClient(
    custom_dns=None,      # Optional: Custom DNS resolver IP
    require_dnssec=False, # Optional: Reject non-DNSSEC records
    user_agent="my-app/1.0",
    http_timeout=30.0
)
```

#### Methods

##### `verify(url: str) -> VerificationResult`

Perform full DIVE verification for a URL.

**Returns**: [`VerificationResult`](#verificationresult) object.

**Example**:

```python
result = client.verify("https://example.com/file.tar.gz")
if result.accepted:
    print("Resource is authentic!")
else:
    print(f"Rejected: {result.failure_reason}")
```

##### `close()`

Close the underlying HTTP client.

**Example**:

```python
client.close()
```

##### Context Manager

```python
with DiveClient() as client:
    result = client.verify("https://example.com/file.tar.gz")
```

---

### `VerificationResult`

Contains the outcome of a DIVE verification.

#### Attributes

| Attribute          | Type                       | Description                                        |
| ------------------ | -------------------------- | -------------------------------------------------- |
| `url`              | `str`                      | Verified URL.                                      |
| `accepted`         | `bool`                     | `True` if the resource is accepted.                |
| `report_only`      | `bool`                     | `True` if the policy is in report-only mode.       |
| `failure_reason`   | `Optional[str]`            | Reason for rejection (e.g., `signature-mismatch`). |
| `final_decision`   | `Optional[str]`            | `"blocked"` or `"allowed-report-only"`.            |
| `scope`            | `Optional[str]`            | Matched scope (e.g., `"strict"`).                  |
| `hash_algorithm`   | `Optional[str]`            | Hash algorithm used (e.g., `"sha256"`).            |
| `hex_digest`       | `Optional[str]`            | Hex digest of the resource.                        |
| `signature_valid`  | `bool`                     | `True` if at least one signature was valid.        |
| `key_resolution`   | `List[KeyResolutionEntry]` | List of key resolution attempts.                   |
| `dive_sig_header`  | `Optional[str]`            | Raw `DIVE-Sig` header value.                       |
| `dnssec_validated` | `bool`                     | `True` if DNS records were DNSSEC-validated.       |
| `policy_domain`    | `Optional[str]`            | Domain of the applied policy.                      |
| `policy_fqdn`      | `Optional[str]`            | FQDN of the resource.                              |
| `body`             | `Optional[bytes]`          | Resource body (only if `accepted=True`).           |

#### Methods

##### `to_report(user_agent: str) -> dict`

Generate a failure report (RFC-compliant JSON).

**Example**:

```python
if not result.accepted:
    report = result.to_report("my-app/1.0")
    print(report)
```

---

## DNS Resolution

OpenDIVE resolves DNS records for `_dive` (policy) and `_divekey` (keys).

### Functions

#### `get_dive_record_walk(fqdn: str, custom_dns: Optional[str]) -> List[dict]`

Walk up the domain tree to find the applicable `_dive` policy record.

**Example**:

```python
from dive.dns import get_dive_record_walk
records = get_dive_record_walk("sub.example.com")
```

#### `get_key_record_walk(fqdn: str, key_id: str, custom_dns: Optional[str]) -> List[dict]`

Walk up the domain tree to find a `_divekey` record.

**Example**:

```python
from dive.dns import get_key_record_walk
keys = get_key_record_walk("sub.example.com", "key1")
```

---

## Cryptographic Operations

### Functions

#### `sign_hash(data: bytes, private_key_b64: str, sig_algorithm: str, hash_algorithm: str) -> dict`

Hash the data and sign the digest.

**Returns**: Dict with `hash_algorithm`, `digest`, `sig_algorithm`, and `signature`.

**Example**:

```python
from dive.crypto import sign_hash
result = sign_hash(
    b"file content",
    private_key_b64="...",
    sig_algorithm="ed25519",
    hash_algorithm="sha256"
)
```

#### `verify_hash(data: bytes, signature_b64: str, public_key_b64: str, sig_algorithm: str, hash_algorithm: str) -> bool`

Verify a signature over hashed data.

**Example**:

```python
from dive.crypto import verify_hash
valid = verify_hash(
    b"file content",
    signature_b64="...",
    public_key_b64="...",
    sig_algorithm="ed25519",
    hash_algorithm="sha256"
)
```

---

## Key Management

### Functions

#### `generate_base64_keypair(alg: str = "ed25519") -> dict`

Generate a new Ed25519/Ed448 key pair.

**Returns**: Dict with `algorithm`, `private_key` (base64), and `public_key` (base64).

**Example**:

```python
from dive.keys import generate_base64_keypair
keys = generate_base64_keypair("ed25519")
```

---

## Error Handling

OpenDIVE raises the following exceptions:

| Exception                     | Description                              |
| ----------------------------- | ---------------------------------------- |
| `DiveRecordNotFound`          | No `_dive` or `_divekey` record found.   |
| `DiveRecordInvalid`           | Record is malformed or invalid.          |
| `UnsupportedAlgorithm`        | Unsupported hash or signature algorithm. |
| `SignatureVerificationFailed` | Signature verification failed.           |

**Example**:

```python
from dive.dns import DiveRecordNotFound

try:
    records = get_dive_record_walk("example.com")
except DiveRecordNotFound:
    print("No DIVE policy for this domain.")
```

---

## Advanced Usage

### Custom DNS Resolvers

Override the default DNS resolver:

```python
client = DiveClient(custom_dns="8.8.8.8")
```

### Caching

OpenDIVE uses an in-memory cache for DNS records. Cache TTL is controlled by the `cache` parameter in DNS records.

### Parallel Verification

For performance, resolve DNS records concurrently with HTTP downloads:

```python
import threading

def verify_in_background(client, url):
    result = client.verify(url)
    print(result.accepted)

thread = threading.Thread(target=verify_in_background, args=(client, "https://example.com/file"))
thread.start()
```

---

## Examples

### 1. Basic Verification

```python
from dive.client import DiveClient

client = DiveClient(require_dnssec=True)
result = client.verify("https://example.com/file.tar.gz")

if result.accepted:
    with open("file.tar.gz", "wb") as f:
        f.write(result.body)
else:
    print(f"Rejected: {result.failure_reason}")
```

### 2. Key Generation and Signing

```python
from dive.keys import generate_base64_keypair
from dive.crypto import sign_hash

# Generate keys
keys = generate_base64_keypair("ed25519")

# Sign a file
with open("file.tar.gz", "rb") as f:
    data = f.read()

result = sign_hash(
    data,
    private_key_b64=keys["private_key"],
    sig_algorithm="ed25519",
    hash_algorithm="sha256"
)

print(f"DIVE-Sig: key1:sha256:{result['signature']}")
```

### 3. DNS Inspection

```python
from dive.dns import get_dive_record_walk, get_key_record_walk

# Get policy
policy = get_dive_record_walk("example.com")[0]
print(f"Scopes: {policy.get('scopes', [])}")

# Get key
key = get_key_record_walk("example.com", "key1")[0]
print(f"Algorithm: {key.get('sig')}")
```

---

## Notes

- **DNSSEC**: Always enable DNSSEC validation in production (`require_dnssec=True`).
- **Performance**: For high-throughput applications, consider:
  - Persistent caching (e.g., Redis).
  - Parallel DNS resolution.
- **Custom Scopes**: Not supported in this release. Use `strict` scope.
- **Thread Safety**: `DiveClient` is thread-safe for concurrent verifications.
