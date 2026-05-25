# KDNA Core Swift

Native Swift implementation of the KDNA Protocol core library — zero dependencies, pure logic.

KDNA (Knowledge DNA) is an open protocol for encoding human-verified domain judgment into structured assets that AI agents can load, verify, and evolve.

This package is the Swift counterpart to [`@aikdna/kdna-core`](https://github.com/aikdna/KDNA/tree/main/packages/kdna-core) (JavaScript). It provides the same core capabilities for native macOS and iOS applications.

## What It Does

- **Load** KDNA domain packages from the filesystem
- **Validate** domain structure and cross-file references
- **Format** domain context for injection into LLM system prompts
- **Classify** tasks to determine which domain sections are relevant
- **Build judgment pipelines** — pre-filter, system prompt injection, post-validation

## Installation

Add via Swift Package Manager:

```swift
// Package.swift
dependencies: [
    .package(url: "https://github.com/aikdna/kdna-core-swift.git", from: "0.1.0")
]
```

Or in Xcode: `File → Add Packages → https://github.com/aikdna/kdna-core-swift`

## Quick Start

```swift
import KDNACore

// Load a domain
let loader = KDNADomainLoader()
let domain = try loader.load(from: URL(filePath: "/path/to/domain"))

// Format for agent context
let context = loader.formatContext(domain)
print(context)

// Validate
let issues = KDNADomainValidator.validate(domain)
```

## Architecture

| File | Description |
|------|-------------|
| `KDNCoreTypes.swift` | Codable structs for all KDNA domain types (Domain, Axiom, Ontology, Framework, Misunderstanding, SelfCheck, etc.) |
| `KDNADomainLoader.swift` | Domain loading, scanning, task classification, context formatting |
| `KDNADomainValidator.swift` | Structural lint, cross-file validation, ID uniqueness |
| `KDNJudgmentPipeline.swift` | Pre-filtering, system prompt construction, post-validation of agent outputs |

## Relationship to KDNA Ecosystem

```
┌──────────────────────────────────┐
│        KDNA Protocol (SPEC)       │  ← Open standard
├──────────────────────────────────┤
│  kdna-core (JS)  │ kdna-core-swift│  ← Core libraries (Apache 2.0)
├──────────────────────────────────┤
│  kdna-cli · kdna-studio · apps   │  ← Tools and applications
└──────────────────────────────────┘
```

This library is used by [KDNAChat](https://github.com/aikdna/kdnachat) for macOS.

## License

Apache 2.0 — see [LICENSE](LICENSE).

## Related

- [KDNA Protocol](https://github.com/aikdna/kdna) — Specification and JS core library
- [KDNA Registry](https://github.com/aikdna/kdna-registry) — Domain catalog
- [kdna-cli](https://github.com/aikdna/kdna-cli) — CLI tools
- [aikdna.com](https://aikdna.com) — Website
