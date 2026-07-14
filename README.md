# KDNA Core Swift

[![CI](https://github.com/aikdna/kdna-core-swift/actions/workflows/ci.yml/badge.svg)](https://github.com/aikdna/kdna-core-swift/actions/workflows/ci.yml) [![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

Swift beta component of the KDNA toolchain for native Apple runtimes.

KDNA Core is the official KDNA judgment-asset format and runtime loading
contract. `.kdna` assets are created, inspected, validated, planned, loaded,
and consumed through the official KDNA toolchain. This package implements the
Swift runtime side for local `.kdna` files. JS Core is the current first-run
public beta baseline; Swift Core is beta until shared conformance evidence is
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
.package(url: "https://github.com/aikdna/kdna-core-swift.git", from: "0.4.0")
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

// Developer compatibility APIs also exist for fixtures. Public runtime use
// should start from a packaged .kdna file and the LoadPlan path above.
```

### Opt-in Runtime Capsule 2

The existing `KDNARuntime.load(...)` API continues to return the frozen
Runtime Capsule 1 shape. Call `loadV2` explicitly when a consumer needs named
A/C/E digest evidence and a delivery digest P:

```swift
let capsule2 = try KDNARuntime.loadV2(
    assetURL: fileURL,
    expected: KDNAExpectedDigests(
        asset: KDNAExpectedDigest(value: receiptAssetDigest, source: "install_receipt")
    )
)

let deliveryDigest = try KDNACapsuleV2.computeDeliveryDigest(capsule2)
let capsule1 = try KDNACapsuleV2.adaptToV1(capsule2)
```

Capsule 2 snapshots the packaged file once, computes A from those exact bytes,
C from the canonical content tree, and E from the raw `kdna.json` and
`payload.kdnab` entry set. Mismatched evidence blocks Capsule emission. P is
SHA-256 over strict RFC 8785 JCS bytes of the delivered Capsule and is not
embedded in the Capsule itself. `KDNAJCS` rejects non-finite numbers rather
than converting them to `null`.

Direct Capsule 1 loading and Capsule 2 adaptation emit the same frozen wire
shape. Capsule 1 preserves a manifest's legacy `open`, `protected`, or
`runtime` access spelling, while LoadPlan and Capsule 2 use the canonical
`public`, `licensed`, or `remote` value for policy decisions. Its trace uses
the cross-language loader identifier `kdna-core`.

All public Capsule value types conform to `Sendable`. Decoding Capsule 1 or 2
is fail closed: required-but-nullable fields must be present, unknown object
properties are rejected, and nested trace, signature, digest, compatibility,
and extension values are validated before a Capsule value is returned.

### Digest vocabulary

- `KDNAAsset.assetDigest` is the SHA-256 digest of the complete `.kdna` file
  bytes.
- `VerifyResult.contentDigest` is the canonical content-tree digest. Binary
  entries such as `payload.kdnab` are hashed as their original bytes.
- `checksums.json.entry_set_digest` covers `kdna.json` and `payload.kdnab`
  under `kdna-runtime-entry-set-v1`. Existing KDNA 1.0 assets may use the
  deprecated `checksums.json.asset_digest` alias; if both are present they must
  be identical.
- Runtime Capsule 1.0 and external grant v1 retain their existing
  `asset_digest`/`asset.digest` wire names for this entry-set binding.
- Runtime Capsule 2 exposes these values as `digests.asset`,
  `digests.content`, and `digests.runtime_entry_set`. Its delivery digest uses
  the separate `kdna-capsule-jcs-v1` basis.

Use `KDNAContentDigest.computeValidated(asset:reader:)` when computing a
digest directly so malformed JSON is handled as an error. The older
non-throwing `compute` overload remains temporarily for source compatibility
and never returns a value matching the `sha256:` digest shape on invalid input.

## What It Does

- **Open and verify** local `.kdna` runtime files
- **Plan runtime loading** through LoadPlan before emitting judgment context
- **Emit authorized Runtime Capsules** with the same profile-specific context
  shapes as the JavaScript Core
- **Validate** developer fixtures for compatibility testing
- **Format** loaded judgment context for native application integration
- **Route / compose / match** through beta Swift APIs used by native experiments

## Architecture

| File | Description |
|------|-------------|
| `KDNCoreTypes.swift` | Codable structs for all KDNA domain types (Domain, Axiom, Ontology, Framework, Misunderstanding, SelfCheck, etc.) |
| `KDNADomainLoader.swift` | Domain loading, scanning, task classification, context formatting |
| `KDNADomainValidator.swift` | Structural lint, cross-file validation, ID uniqueness |
| `KDNAExternalKeyGrant.swift` | RFC-0019 signature/binding verification, X25519 unwrap, and in-memory decryption |
| `KDNACapsuleV2.swift` | Opt-in A/C/E evidence, strict RFC 8785 JCS/P, Capsule 2 model, and v2-to-v1 adapter |
| `KDNAStrictCodable.swift` | Shared fail-closed Capsule decoding helpers |
| `KDNJudgmentPipeline.swift` | Pre-filtering, system prompt construction, post-validation of agent outputs |
| `KDNARouter.swift` | **7-State Domain Router** — full routing pipeline (Intent Gate → Negative Match → Domain Fit → Trust Gate → Ambiguity Gate) |
| `KDNAComposer.swift` | **Multi-Domain Composer** — combines primary + constraint domains with conflict detection |
| `KDNATrust.swift` | **Trust Verifier** — signature, yank, and license verification |

### Compatibility Status

| Capability | Status |
|------------|--------|
| Open local `.kdna` runtime containers | Beta |
| Verify local `.kdna` container digests | Beta |
| LoadPlan authorization planning | Beta |
| CBOR payload and encrypted-envelope decoding | Beta |
| Runtime Capsule (`index` / `compact` / `scenario` / `full`) | Beta |
| Opt-in Runtime Capsule 2 A/C/E/P parity | Beta; shared JavaScript golden vector |
| RFC-0019 account/device external grant verification | Beta; shared JS golden vector |
| `KDNAJudgmentProjection` rendering | Beta |
| Developer fixture loading | Developer compatibility |
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

`load` returns a `KDNAContextCapsule`, not the raw payload. Its context follows
the selected `index`, `compact`, `scenario`, or `full` load profile. The older
`loadWithCredential` projection API remains available to native UI code, but
Agent consumption should use the Capsule path.

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

## Consumption traces

Applications can present the result of a KDNA consumption decision through the
shared trace model and projector. A trace explains which asset was selected,
which advisors were accepted or rejected, the active budget profile, and the
decision provenance. It is an application-facing record, not a second asset
format and not a content endorsement.

Use the CLI and `@aikdna/kdna-eval` as the reference for route, compose, and
replay policy. Native clients should consume compatible traces rather than
inventing independent trust or promotion rules.

## License

Apache 2.0 — see [LICENSE](LICENSE).

## Related

- [KDNA Core](https://github.com/aikdna/kdna) — Format, JS core library, and launch truth
- [kdna-cli](https://github.com/aikdna/kdna-cli) — CLI tools
- [aikdna.com](https://aikdna.com) — Website
