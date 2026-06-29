# Security Policy

Lupid is a security product. We take vulnerabilities in this SDK seriously and appreciate responsible disclosure.

## Reporting a vulnerability

**Please do not report security issues in public GitHub issues, discussions, or pull requests.**

Use one of these private channels:

1. **GitHub Private Vulnerability Reporting** (preferred) — open a report via the
   **Security → Report a vulnerability** tab on this repository. This keeps the
   report private to the maintainers until a fix is available.
2. **Email** — `security@lupid.ai` (PGP available on request).

Please include:

- the affected package(s) and version(s),
- a description of the issue and its impact,
- steps to reproduce or a proof-of-concept,
- any suggested remediation.

## What to expect

- **Acknowledgement** within **3 business days**.
- An initial **assessment + severity** within **10 business days**.
- We will keep you updated on remediation progress and coordinate a disclosure
  timeline with you. We aim to ship fixes for confirmed high/critical issues
  promptly and will credit reporters who wish to be acknowledged.

## Scope

In scope: `@lupid/sdk` and `@lupid/react` in this repository (policy-enforcement
bypass, PII-masking failures, fail-open regressions, credential/secret handling,
supply-chain/dependency issues).

Out of scope: the separate Lupid control plane / cloud (report those through the
same channels, noting the component), and issues in third-party dependencies that
are already publicly disclosed (please link the advisory).

## Supported versions

The latest minor release line receives security fixes. Pre-1.0, we may require an
upgrade to the latest patch to receive a fix.
