# KDNA Core Swift

Native Swift implementation of the KDNA Protocol core library — zero dependencies, pure logic.

KDNA (Knowledge DNA) is an open protocol for encoding human-verified domain judgment into structured assets that AI agents can load, verify, and evolve.

This package is the Swift counterpart to [`@aikdna/kdna-core`](https://github.com/aikdna/KDNA/tree/main/packages/kdna-core) (JavaScript). It is the foundation for native macOS and iOS applications that load, validate, and route KDNA cognitive assets. It provides the same core capabilities for native Apple platform applications.



## Install

### Swift Package Manager

Add to your Package.swift:

```
.package(url: "https://github.com/aikdna/kdna-core-swift.git", from: "0.2.0")
```

Then add `KDNACore` to your target dependencies:

```
.product(name: "KDNACore", package: "kdna-core-swift")
```

### Quick Start

```swift
import KDNACore

// Open a .kdna asset
let reader = KDNAAssetReader()
let asset = try reader.open(url: fileURL)
let manifest = try reader.readManifest(asset: asset)

// Verify integrity
let result = reader.verifySync(asset)
print("Content digest:", result.contentDigest ?? "")

// Load a domain
if let domain = KDNADomainLoader.load(path: "/path/to/domain") {
    let context = KDNADomainLoader.formatContext(domain)
    print(context)
}
```

## What It Does
## What It Does

- **Load** KDNA domain assets from the filesystem
- **Validate** domain structure and cross-file references
- **Format** domain context for injection into LLM system prompts
- **Classify** tasks to determine which domain sections are relevant
- **Route** tasks to the correct domain using a 7-state decision engine (Negative Match First → Domain Fit → Trust Gate → Ambiguity Gate)
- **Compose** multiple domains with conflict detection (stance, axiom, term conflicts)
- **Verify** trust: signature presence, yank status, license validity
- **Match** tasks against installed domains (keyword scan with does_not_apply_when exclusion)
- **Build judgment pipelines** — pre-filter, system prompt injection, post-validation

## Architecture

| File | Description |
|------|-------------|
| `KDNCoreTypes.swift` | Codable structs for all KDNA domain types (Domain, Axiom, Ontology, Framework, Misunderstanding, SelfCheck, etc.) |
| `KDNADomainLoader.swift` | Domain loading, scanning, task classification, context formatting |
| `KDNADomainValidator.swift` | Structural lint, cross-file validation, ID uniqueness |
| `KDNJudgmentPipeline.swift` | Pre-filtering, system prompt construction, post-validation of agent outputs |
| `KDNARouter.swift` | **7-State Domain Router** — full routing pipeline (Intent Gate → Negative Match → Domain Fit → Trust Gate → Ambiguity Gate) |
| `KDNAComposer.swift` | **Multi-Domain Composer** — combines primary + constraint domains with conflict detection |
| `KDNATrust.swift` | **Trust Verifier** — signature, yank, and license verification |

### Feature Parity with kdna-cli (JS)

| Capability | JS CLI | Swift |
|------------|:---:|:---:|
| load domain | ✅ | ✅ |
| validate | ✅ | ✅ |
| formatContext | ✅ | ✅ |
| classify task | ✅ | ✅ |
| preFilter | ✅ | ✅ |
| systemPrompt | ✅ | ✅ |
| postValidate | ✅ | ✅ |
| **route (7-state)** | ✅ | ✅ |
| **compose (multi-domain)** | ✅ | ✅ |
| **verify trust** | ✅ | ✅ |
| **match (keyword)** | ✅ | ✅ |
| **available (inventory)** | ✅ | ✅ |
| install/registry | ✅ | N/A (CLI) |
| pack/publish | ✅ | N/A (CLI) |

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

This library is used by [KDNAChat](https://github.com/aikdna/kdna-core-swift) for macOS.

## License

Apache 2.0 — see [LICENSE](LICENSE).

## Related

- [KDNA Protocol](https://github.com/aikdna/kdna) — Specification and JS core library
- [KDNA Registry](https://github.com/aikdna/kdna-registry) — Domain catalog
- [kdna-cli](https://github.com/aikdna/kdna-cli) — CLI tools
- [aikdna.com](https://aikdna.com) — Website
