# OpenDIVE: Python Client for Domain-based Integrity Verification Enforcement (DIVE)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![Version: 0.1.1](https://img.shields.io/badge/Version-0.1.1-orange.svg)](https://github.com/diveprotocol/opendive-client/releases)
[![Status: Alpha](https://img.shields.io/badge/Status-Alpha-red.svg)](https://github.com/diveprotocol/opendive-client)

**OpenDIVE** is a Python client library for the **DIVE protocol** (Domain-based Integrity Verification Enforcement), a cryptographic protocol that leverages **DNSSEC** to verify the integrity and authenticity of web resources. DIVE operates as an additional security layer above HTTP/HTTPS, ensuring that resources are signed and validated against DNS-published keys.

---

## Features

- **DNSSEC-backed verification**: Uses DNS TXT records (`_dive`, `_divekey`) to publish policies and public keys.
- **Cryptographic signatures**: Supports **Ed25519** and **Ed448** for signing, and **SHA-256/384/512** for hashing.
- **CLI tool**: Includes commands for verification, key generation, signing, and DNS inspection.
- **Incremental deployment**: Works alongside existing infrastructure without breaking non-DIVE clients.
- **Reporting**: Sends verification failure reports to a configurable endpoint.

---

## Installation

### From PyPI (Alpha Release)

```bash
pip install opendive-client
```

### From Source

```bash
git clone https://github.com/diveprotocol/opendive-client.git
cd opendive-client
pip install -e .
```

### Dependencies

- Python 3.8+
- `dnspython` (DNSSEC resolution)
- `cryptography` (Ed25519/Ed448 support)
- `httpx` (HTTP client)
- `click` (CLI)

---

## Usage

### CLI Commands

OpenDIVE provides a CLI for common operations:

```bash
# Verify a resource
opendive verify https://example.com/file.tar.gz

# Download a resource (only if DIVE verification passes)
opendive download https://example.com/file.tar.gz

# Generate a key pair
opendive keygen --alg ed25519 --key-id mykey --domain example.com

# Sign a file
opendive sign myfile.tar.gz --private-key <base64_private_key> --key-id mykey

# Inspect DNS records
opendive dns example.com --key-id mykey
```

### Python Library

```python
from dive.client import DiveClient

client = DiveClient(require_dnssec=True)
result = client.verify("https://example.com/file.tar.gz")

if result.accepted:
    print("Resource is authentic!")
else:
    print(f"DIVE rejected resource: {result.failure_reason}")
```

---

## Documentation

### DIVE Protocol

- [Draft RFC](https://datatracker.ietf.org/doc/draft-callec-dive/) (Work in Progress)
- [DIVE Website](https://diveprotocol.org)

### OpenDIVE API

- [CLI Reference](docs/cli.md) (TODO)
- [Python API](docs/api.md) (TODO)

---

## Development

### Running Tests

```bash
pytest tests/
```

### Contributing

Pull requests are welcome! For major changes, please open an issue first.

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

## Security

For security issues, see [SECURITY.md](SECURITY.md).

---

## Contact

- **Author**: Matéo Florian CALLEC
- **Email**: mateo@callec.net
- **GitHub**: [@diveprotocol](https://github.com/diveprotocol)
