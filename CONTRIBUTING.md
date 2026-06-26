# Contributing to kdna-core-swift

This is the Swift implementation of the KDNA Core v1 spec. It mirrors the
JavaScript `@aikdna/kdna-core` package, focusing on macOS-first consumption
from the Studio Swift app and other Swift-based tools.

## Prerequisites

- **macOS 13+** (for CryptoKit and modern Swift Concurrency)
- **Swift 5.9+** (check: `swift --version`)
- **Xcode 15+** (for full development; command-line tools are sufficient for `swift build`)
- **Git** (for submitting PRs)

> Cross-platform note: this package targets macOS. Linux Swift is not
> covered by CI. iOS may work but is not officially supported.

## Repository Layout

```
kdna-core-swift/
├── Sources/
│   └── KDNACore/         # Library code (mirrors @aikdna/kdna-core)
├── Tests/
│   └── KDNACoreTests/    # XCTest suite
├── Package.swift         # SwiftPM manifest
├── README.md
├── SECURITY.md
└── CHANGELOG.md
```

## Developer Setup

```bash
git clone https://github.com/aikdna/kdna-core-swift.git
cd kdna-core-swift
swift build          # debug build
swift test           # run XCTest suite
swift build -c release
```

### Xcode

Open `Package.swift` in Xcode. The `KDNACore` library and
`KDNACoreTests` test target are auto-detected.

## Available Commands

| Command | Purpose |
|---------|---------|
| `swift build` | Debug build |
| `swift build -c release` | Release build |
| `swift test` | Run all XCTest cases |
| `swift test --filter KDNACoreTests.testName` | Run a single test |
| `swift package describe` | Inspect package metadata |
| `swift package generate-xcodeproj` | (legacy; Xcode auto-detects `Package.swift` now) |

## Cross-Implementation Parity

This package **must** stay behaviorally equivalent to `@aikdna/kdna-core`
in the following areas:

- LoadPlan v1 states and transitions
- Canonical container format
- Crypto profile: `kdna-password-protected-v1` (Argon2id + AES-KW + AES-GCM)
- Manifest schema validation

Before opening a PR, run the cross-language golden vectors in the
JavaScript repo (`packages/kdna-core/test-vectors/golden-vectors.js`)
and confirm identical outputs. If a divergence is intentional, document
it in the PR description with rationale.

## Contribution Types

### 1. Crypto / Loader Fix

If you find a divergence with the JS implementation, the JS repo is
authoritative. Open a PR here with a test case demonstrating the
divergence, then a fix.

### 2. Platform Adaptation

Improvements specific to macOS / iOS (e.g., Keychain integration,
Secure Enclave use) belong here. They must not change wire formats.

### 3. Performance / API Ergonomics

Internal improvements are welcome. Public API must remain stable across
minor versions; major API changes require coordination with the JS
implementation.

### 4. Documentation

Improvements to README, SECURITY.md, or inline doc comments.

## Quality Requirements

All contributions must:
- Pass `swift test` (no failing or skipped tests without explanation)
- Maintain parity with the JavaScript reference where applicable
- Follow Swift API Design Guidelines
- Use Swift Concurrency (`async`/`await`) for new I/O code
- Not depend on third-party packages without discussion (this package
  currently has zero runtime dependencies)

## License

- Code contributions: Apache 2.0
