# Contributing to DIVE Protocol

First off, thank you for considering contributing to the DIVE (Domain-based Integrity Verification Enforcement) protocol! Your contributions help make web security more robust and accessible.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Enhancements](#suggesting-enhancements)
  - [Pull Requests](#pull-requests)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
  - [Code Formatting](#code-formatting)
  - [Commit Messages](#commit-messages)
  - [Branch Naming](#branch-naming)
- [Testing](#testing)
- [Documentation](#documentation)
- [RFC Compliance](#rfc-compliance)
- [Community](#community)

---

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). Please read it before contributing.

---

## How Can I Contribute?

### Reporting Bugs

1. **Check existing issues** to avoid duplicates
2. **Create a new issue** with:
   - Clear title and description
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Python version, etc.)
   - Relevant logs or screenshots

**Template:**

```markdown
### Description

[Clear description of the issue]

### Steps to Reproduce

1. [First step]
2. [Second step]
3. [And so on...]

### Expected Behavior

[What you expected to happen]

### Actual Behavior

[What actually happened]

### Environment

- OS: [e.g., Ubuntu 22.04]
- Python: [e.g., 3.10.6]
- DIVE Version: [e.g., 0.1.0]
```

---

### Suggesting Enhancements

1. **Check existing issues** for similar suggestions
2. **Create a new issue** with:
   - Clear use case explanation
   - Proposed solution (if you have one)
   - Any relevant RFC sections

**Template:**

```markdown
### Problem

[Description of the problem this solves]

### Solution

[Your proposed enhancement]

### RFC Reference

[Relevant sections from draft-callec-dive if applicable]
```

---

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Follow coding standards** (see below)
3. **Add tests** for new functionality
4. **Update documentation** if needed
5. **Submit the PR** with:
   - Clear title and description
   - Reference to related issue(s)
   - Test results

**PR Template:**

```markdown
### Description

[What this PR does]

### Related Issue

Closes #XXX

### Changes Made

- [Change 1]
- [Change 2]

### Testing

[How you tested these changes]

### RFC Compliance

[If applicable, reference RFC sections this addresses]
```

---

## Development Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/diveprotocol/opendive-client.git
   cd opendive-client
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```

3. Run tests:
   ```bash
   pytest
   ```

---

## Coding Standards

### Code Formatting

This project uses a **code formatter** to maintain consistent style. Before submitting changes:

1. Run the formatter:

   ```bash
   ./scripts/format.sh
   ```

2. Key formatting rules:
   - 4-space indentation
   - PEP 8 compliance
   - Type hints for all functions
   - Docstrings for public APIs

### Commit Messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types:**

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Test-related changes
- `chore`: Maintenance tasks

**Example:**

```
feat(dns): add DNSSEC validation timeout configuration

This adds a configurable timeout for DNSSEC validation attempts,
which helps in environments with slow DNS resolvers.

Closes #42
```

### Branch Naming

Use descriptive branch names following this pattern:

```
<type>/<short-description>
```

**Examples:**

- `feat/dns-timeout-config`
- `fix/key-resolution-bug`
- `docs/update-readme`

---

## Testing

1. All new features require tests
2. Run the full test suite before submitting:
   ```bash
   pytest --cov=dive tests/
   ```
3. Test coverage should not decrease

---

## Documentation

1. Update relevant documentation for new features
2. Add docstrings to all public functions and classes
3. Follow [Google-style docstrings](https://google.github.io/styleguide/pyguide.html#38-comments-and-docstrings)

**Example:**

```python
def verify_signature(data: bytes, signature: str, public_key: str) -> bool:
    """Verify a DIVE signature against provided data.

    Args:
        data: The data to verify
        signature: Base64-encoded signature
        public_key: Base64-encoded public key

    Returns:
        True if signature is valid, False otherwise

    Raises:
        ValueError: If inputs are malformed
    """
    ...
```

---

## RFC Compliance

All contributions must maintain compliance with the [DIVE RFC draft](https://datatracker.ietf.org/doc/draft-callec-dive/):

1. Reference relevant RFC sections in PR descriptions
2. Add compliance notes to documentation
3. Include test cases that verify RFC requirements

---

## Community

- **Discussions**: Use GitHub Discussions for design questions
- **Chat**: Join our Matrix channel `#dive-protocol:matrix.org`
- **Meetings**: Bi-weekly community calls (see GitHub for schedule)

---

## Recognition

All contributors will be:

1. Added to the [CONTRIBUTORS.md](CONTRIBUTORS.md) file
2. Recognized in release notes
3. Invited to co-author relevant publications

---

Thank you for contributing to make the web more secure with DIVE!
