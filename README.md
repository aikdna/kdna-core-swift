# KDNA Core Swift

[![CI](https://github.com/aikdna/kdna-core-swift/actions/workflows/ci.yml/badge.svg)](https://github.com/aikdna/kdna-core-swift/actions/workflows/ci.yml) [![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

Swift pre-release component of the KDNA toolchain for native Apple runtimes.

KDNA Core is the official KDNA judgment-asset format and runtime loading
contract. `.kdna` assets are created, inspected, validated, planned, loaded,
and consumed through the official KDNA toolchain. This package implements the
Swift runtime side for local `.kdna` files. JS Core is the current first-run
public pre-release baseline; Swift Core remains pre-release until shared conformance evidence is
published.

This package is the Swift counterpart to [`@aikdna/kdna-core`](https://github.com/aikdna/kdna/tree/main/packages/kdna-core) (JavaScript). It is the foundation for native macOS and iOS applications that need to plan-load, verify, and project local KDNA runtime files.

Authorization and runtime-load planning are defined in `aikdna/kdna`, not in
app repositories. Native apps should render authorization UI from
`KDNARuntime.planLoad(...)` and should not infer load permission directly from
raw manifest fields.



## Install

### Swift Package Manager

Add to your Package.swift:

```
.package(url: "https://github.com/aikdna/kdna-core-swift.git", from: "0.20.0")
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
    // Agents consume the verified Runtime Capsule, never raw asset entries.
    let capsule = try KDNARuntime.load(assetURL: fileURL)
    print(capsule.context)
} else {
    print("Required action:", plan.required_action)
}

// Verify integrity
let result = reader.verifySync(asset)
print("Content digest:", result.contentDigest ?? "")

// Developer fixture APIs are separate from the packaged Runtime path above.
```

`compatibility.min_loader_version` is a strict `x.y.z` loader package
coordinate. The current source candidate reports
`KDNALoaderCompatibility.currentVersion` as `0.21.0`; the latest published
Swift package release remains `0.20.0`. Components
with leading zeros and coordinates with prefixes, prerelease suffixes, build
metadata, missing components, or whitespace are invalid. A structurally valid
asset that requires a newer loader is blocked before projection with
`KDNA_LOADER_VERSION_UNSUPPORTED`. `verifySync`, `planLoad`, and both Runtime
load entry points enforce the same decision.

### Current Runtime contract

`KDNARuntime.load(...)` returns the sole current `KDNARuntimeCapsule`. The
Capsule wire type is `kdna.runtime-capsule` and its contract version is
`0.1.0`. There is no generation selector or adapter in the public Runtime API.

```swift
let capsule = try KDNARuntime.load(
    assetURL: fileURL,
    expected: KDNAExpectedDigests(
        asset: KDNAExpectedDigest(
            value: receiptAssetDigest,
            source: "install_receipt"
        )
    )
)
let deliveryDigest = try KDNARuntimeCapsuleCore.computeDeliveryDigest(capsule)
```

The Runtime snapshots the packaged file once and emits explicit digest
evidence:

- A uses `kdna.digest-basis.container-bytes` for the exact packaged bytes.
- C uses `kdna.digest-basis.content-tree` for the canonical content tree.
- E uses `kdna.digest-basis.runtime-entry-set` for `kdna.json` and
  `payload.kdnab`.
- P uses `kdna.canonicalization.runtime-capsule-jcs` over strict RFC 8785 JCS
  bytes of the delivered Capsule.

A mismatch blocks delivery. Required-but-nullable fields must be present,
closed objects reject unknown properties, and non-finite numbers are rejected
instead of being rewritten. The public Capsule graph is `Sendable`.

The same authority defines the execution chain:

```text
ConsumptionPlan
→ Agent Host capability negotiation
→ correlated Host request and receipt
→ terminal JudgmentTrace
```

Swift validates the Plan digest, task and asset identity, Capsule contract,
A/C/E/P evidence, projected-character budget, request/receipt correlation,
terminal status, and exact budget evidence. Host completion is recorded
separately from semantic consumption or behavioral influence. Budget limits
and observed integer usage must remain within JavaScript's exact safe integer
range; values outside that range fail closed before Swift integer conversion.

LoadPlan, Runtime Capsule, digest evidence, ConsumptionPlan, Agent Host, and
JudgmentTrace schemas are byte-for-byte resources pinned to
`aikdna/kdna@3676ab0e4b54b83c4193eef3519b19cc6d0cd245` (Core `0.21.0`
Development Preview candidate).
SHA-256 resource locks make missing or drifted schemas fail closed. Date-time
and URI formats follow the canonical Node validation boundaries. Manifest
encryption declarations and the actual CBOR envelope must agree before
authorization; encrypted payloads are schema validated after authorized
in-memory decryption and before Runtime delivery.

### Digest vocabulary

- `KDNAAsset.assetDigest` is the SHA-256 digest of the complete `.kdna` bytes.
- `VerifyResult.contentDigest` is the canonical content-tree digest; binary
  entries are hashed as their original bytes.
- `checksums.json.entry_set_digest` covers exactly `kdna.json` and
  `payload.kdnab` under `kdna.digest-basis.runtime-entry-set` version `0.1.0`.
- External grants bind the exact packaged asset digest and the declared
  payload entry path as well as asset identity and version.

Use `KDNAContentDigest.computeValidated(asset:reader:)` for direct digest
computation so malformed JSON fails closed.

## What It Does

- **Open and verify** local `.kdna` runtime files
- **Plan runtime loading** through LoadPlan before emitting judgment context
- **Emit authorized Runtime Capsules** with the same profile-specific context
  shapes as the JavaScript Core
- **Validate** developer fixtures for conformance testing
- **Format** loaded judgment context for native application integration
- **Route / compose / match** through pre-release Swift APIs used by native integrations

## Architecture

| File | Description |
|------|-------------|
| `KDNCoreTypes.swift` | Codable structs for all KDNA domain types (Domain, Axiom, Ontology, Framework, Misunderstanding, SelfCheck, etc.) |
| `KDNADomainLoader.swift` | Domain loading, scanning, task classification, context formatting |
| `KDNADomainValidator.swift` | Structural lint, cross-file validation, ID uniqueness |
| `KDNAExternalKeyGrant.swift` | RFC-0019 signature/binding verification, X25519 unwrap, and in-memory decryption |
| `KDNARuntimeCapsule.swift` | Current Runtime Capsule, A/C/E evidence, and strict RFC 8785 JCS/P |
| `KDNARuntimeContracts.swift` | ConsumptionPlan, Agent Host negotiation/request/receipt, budget evidence, and JudgmentTrace validation |
| `KDNAStrictCodable.swift` | Shared fail-closed Capsule decoding helpers |
| `KDNJudgmentPipeline.swift` | Pre-filtering, system prompt construction, post-validation of agent outputs |
| `KDNARouter.swift` | **7-State Domain Router** — full routing pipeline (Intent Gate → Negative Match → Domain Fit → Trust Gate → Ambiguity Gate) |
| `KDNAComposer.swift` | **Multi-Domain Composer** — combines primary + constraint domains with conflict detection |
| `KDNATrust.swift` | **Trust Verifier** — signature, yank, and license verification |

### Compatibility Status

| Capability | Status |
|------------|--------|
| Open local `.kdna` runtime containers | Pre-release |
| Verify local `.kdna` container digests | Pre-release |
| LoadPlan authorization planning | Pre-release |
| CBOR payload and encrypted-envelope decoding | Pre-release |
| Current Runtime Capsule (`index` / `compact` / `scenario` / `full`) | Pre-release; shared JavaScript golden vector |
| A/C/E/P and Plan/Host/Trace parity | Pre-release; shared JavaScript contract fixtures |
| RFC-0019 account/device external grant verification | Pre-release; shared JS golden vector |
| `KDNAJudgmentProjection` rendering | Pre-release |
| Developer fixture loading | Conformance-only |
| Route / compose / match APIs | Experimental |
| Complete JS parity | Not claimed; requires fixed shared conformance evidence |

RFC-0019 callers persist the highest verified `status_version` and verified
wall-clock value in the platform SecretStore, then pass them as
`minimumStatusVersion` and `minimumVerifiedTime`. Rollback fails closed. Call
`dispose()` when a verified authorization is no longer needed to clear its
in-memory CEK eagerly.

## Runtime Authorization Contract

The source of truth is `aikdna/kdna`:

- `specs/kdna-authorization-contract.md`
- `schema/load-plan.schema.json`
- `conformance/authorization/cases.json`
- `conformance/authorization/goldens/*.loadplan.json`

Swift Core consumes that contract through `KDNARuntime.planLoad(assetURL:environment:)`
and `KDNARuntime.load(assetURL:credential:profile:)`. The current
implementation covers developer fixtures and packed `.kdna` runtime
containers, and is tested against the shared authorization conformance goldens.
Product code should use the returned `KDNALoadPlan.state`, `required_action`,
`can_load_now`, and `issues` fields as its UI/runtime source of truth.

For an account/device asset, construct a `KDNAExternalGrantAuthorization` only
through `authorize(...)`, passing issuer keys pinned by the application and the
device agreement private key loaded from Keychain. The verifier checks the
signature, time window, account, device, asset identity/version/digest, and
encrypted entry before LoadPlan can become ready. Its initializer is private,
so a plain status value cannot manufacture authorization. The CEK stays inside
the in-memory authorization object and is cleared on deinitialization; account
assets never fall back to password loading.

`load` returns a `KDNARuntimeCapsule`, not the raw payload. Its context follows
the selected `index`, `compact`, `scenario`, or `full` load profile.
`loadWithCredential` is the native UI projection API; Agent consumption uses
the Capsule path.

Swift Core must not define access modes, entitlement profiles, issue codes, or
fail-closed policy independently from `aikdna/kdna`.

## Relationship to KDNA Ecosystem

```
┌──────────────────────────────────┐
│     KDNA Asset Container          │  ← Judgment-asset contract
├──────────────────────────────────┤
│  kdna-core (JS)  │ kdna-core-swift│  ← Core libraries (Apache 2.0)
├──────────────────────────────────┤
│  kdna-cli · kdna-studio · apps   │  ← Tools and applications
└──────────────────────────────────┘
```

This library is the Swift runtime bridge for products that need to inspect,
validate, load, or format KDNA-compatible assets locally.

## JudgmentTrace

Applications record Runtime delivery through `KDNAJudgmentTrace`, the strict
schema-backed trace shared with the Node authority. Validation binds the trace
to the exact ConsumptionPlan, Capsule, Agent Host request and receipt,
negotiated capabilities, terminal status, and observed budget evidence. It is
an execution record, not a second asset format or a claim that the model
semantically followed the delivered judgment.

Use the CLI and `@aikdna/kdna-eval` as the reference for route, compose, and
replay policy. Native clients consume the shared trace contract rather than
defining independent trust or promotion rules.

## License

Apache 2.0 — see [LICENSE](LICENSE).

## Related

- [KDNA Core](https://github.com/aikdna/kdna) — Format, JS core library, and launch truth
- [kdna-cli](https://github.com/aikdna/kdna-cli) — CLI tools
- [aikdna.com](https://aikdna.com) — Website
