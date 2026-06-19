# KDNA Core Swift

[![CI](https://github.com/aikdna/kdna-core-swift/actions/workflows/ci.yml/badge.svg)](https://github.com/aikdna/kdna-core-swift/actions/workflows/ci.yml) [![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

Official Swift component of the KDNA toolchain — the official KDNA judgment-asset format and runtime loading contract.

KDNA Core is the official KDNA judgment-asset format. .kdna assets are created, inspected, loaded, and consumed through the official KDNA toolchain. This package is the official Swift component of that toolchain.

This package is the Swift counterpart to [`@aikdna/kdna-core`](https://github.com/aikdna/kdna/tree/main/packages/kdna-core) (JavaScript). It is the foundation for native macOS and iOS applications that load, validate, and route KDNA cognitive assets. It provides the same core capabilities for native Apple platform applications.

Authorization and runtime-load planning are defined in `aikdna/kdna`, not in
app repositories. Native products such as KDNAChat and KDNAStudio should render
authorization UI from `KDNARuntime.planLoad(...)` and should not infer load
permission directly from raw manifest fields.



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

// Plan authorization before loading
let plan = KDNARuntime.planLoad(assetURL: fileURL)
if plan.can_load_now {
    let projection = try KDNARuntime.loadWithCredential(assetURL: fileURL)
    print(projection.prompt)
} else {
    print("Required action:", plan.required_action)
}

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
- **Plan runtime authorization** through LoadPlan before loading protected assets
- **Project authorized v1 runtime payloads** through `KDNAJudgmentProjection`
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
| **licensed entry decrypt** | ✅ | ✅ |
| **LoadPlan authorization conformance** | ✅ | ✅ |
| **JudgmentProjection** | ✅ | ✅ |
| install/registry | legacy | N/A (CLI) |
| pack/publish | ✅ | N/A (CLI) |

## Runtime Authorization Contract

The source of truth is `aikdna/kdna`:

- `specs/kdna-authorization-contract.md`
- `schema/load-plan.schema.json`
- `conformance/authorization/cases.json`
- `conformance/authorization/goldens/*.loadplan.json`

Swift Core consumes that contract through `KDNARuntime.planLoad(assetURL:environment:)`
and `KDNARuntime.loadWithCredential(assetURL:credential:)`. The current
implementation covers v1 source-directory fixtures and packed `.kdna` runtime
containers, and is tested against the shared authorization conformance goldens.
Product code should use the returned `KDNALoadPlan.state`, `required_action`,
`can_load_now`, and `issues` fields as its UI/runtime source of truth.

`loadWithCredential` returns a `KDNAJudgmentProjection`, not the raw payload.
The projection contains minimal task-safe sections and prompt text derived from
authorized `payload.kdnab` content.

Swift Core must not define access modes, entitlement profiles, issue codes, or
fail-closed policy independently from `aikdna/kdna`.

## Relationship to KDNA Ecosystem

```
┌──────────────────────────────────┐
│        KDNA Core v1 format        │  ← Judgment-asset contract
├──────────────────────────────────┤
│  kdna-core (JS)  │ kdna-core-swift│  ← Core libraries (Apache 2.0)
├──────────────────────────────────┤
│  kdna-cli · kdna-studio · apps   │  ← Tools and applications
└──────────────────────────────────┘
```

This library is the Swift runtime bridge for products that need to inspect,
validate, load, or decrypt KDNA-compatible assets locally.

## License

Apache 2.0 — see [LICENSE](LICENSE).

## Related

- [KDNA Core](https://github.com/aikdna/kdna) — Format, JS core library, and launch truth
- [kdna-cli](https://github.com/aikdna/kdna-cli) — CLI tools
- [aikdna.com](https://aikdna.com) — Website
