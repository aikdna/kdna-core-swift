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

`kdna-core-swift` is a public beta support surface for Apple platforms.

| Component | Supported Versions |
|-----------|-------------------|
| KDNA Protocol | Latest tagged release in `aikdna/kdna` |
| kdna-core-swift | Latest mainline beta release |

Older Swift beta versions may receive critical security patches on a
case-by-case basis.

## Security Model

`kdna-core-swift` is a Swift runtime bridge. It must follow the protocol,
crypto profile, LoadPlan, and projection contracts defined by the main
`aikdna/kdna` repository.

For the KDNA Protocol security architecture, see
[GOVERNANCE.md](https://github.com/aikdna/kdna/blob/main/docs/GOVERNANCE.md)
in the main protocol repository.
