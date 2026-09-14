# Security Policy

## Reporting a Vulnerability

Please **do not** report security vulnerabilities through public GitHub issues.

Instead, use one of these private channels:

- **GitHub Private Vulnerability Reporting**: Go to the [Security Advisories](https://github.com/aikdna/kdna-core-swift/security/advisories/new) page
- **Email**: security@aikdna.com

We aim to respond within 72 hours and provide a timeline for resolution within
1 week. Please do not disclose the vulnerability publicly until we have had a
chance to address it.

## Supported Versions

`kdna-core-swift` is a pre-release Core and Read implementation for Apple platforms.

Security support continues to cover the latest tagged KDNA Protocol release
in `aikdna/kdna` and the latest mainline pre-release of `kdna-core-swift`.
Older Swift pre-release versions may receive critical security patches on a
case-by-case basis.

## Current dependency inputs

| Component | Current contract |
|-----------|------------------|
| Swift implementation | Candidate coordinate in `public-contract-binding.json` |
| Core / canonical IR / Read | `kdna.core/0.3.0` / `kdna.canonical-ir/0.2.0` / `kdna.read/0.2.0` |

The exact binding governs this implementation; a newer protocol repository
commit does not automatically change its accepted contract. No candidate tag or
registry release is implied.

## Security Model

Core admission establishes technical validity of captured bytes. It does not
establish authorship, content quality, Creation acceptance, read permission or
action authorization. Read disclosure requires explicit trusted control and
Host providers, with observed scope, identity, timing and policy. Serialized
snapshot or handle data cannot recreate process-local authority. Projection
alone does not grant permission.

Encrypted, signed and checksum-bearing containers remain unavailable where
the current Core rejects those capabilities. Plan admission and execution are
unavailable. The previous loader and its crypto dependencies are preserved
under `retired/` and are outside the current package graph.

Report an admission, disclosure, identity or authority-boundary failure through
the private channels above. Include the exact commit and binding coordinate,
platform/toolchain, and a minimal synthetic reproduction without private keys
or user data.

For the KDNA Protocol security architecture, see
[GOVERNANCE.md](https://github.com/aikdna/kdna/blob/main/docs/GOVERNANCE.md)
in the main protocol repository.
