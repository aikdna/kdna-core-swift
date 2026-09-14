# KDNA Swift Core and Read

A Swift-native implementation of the pinned public Core and Read contract, at candidate coordinate `0.4.0-rc.component-semantics.1`. The Swift package exposes the `KDNACore` library. It uses Foundation, CryptoKit, Darwin and platform zlib with no external package dependencies. SwiftPM declares macOS 13 and iOS 16 deployment targets. CI runs macOS tests and a generic iOS device compilation; the iOS leg does not exercise device runtime behavior. Linux, Windows, Tauri and WKWebView are not verified.

## Core admission

```swift
import Foundation
import KDNACore

let result = KDNACore.admitFile(URL(fileURLWithPath: "asset.kdna"))
if let snapshot = result.snapshot {
    let view = snapshot.inspect()
    let bytes = try KDNAJSON.canonical(view)
    print(String(decoding: bytes, as: UTF8.self))
} else {
    print(result.result)
}
```

`admitBytes(Data)` captures and validates a container. `KDNASnapshot` has no public initializer and returns a value copy from `inspect()`. `KDNAValue` represents the JSON domain; `KDNAKey` compares exact scalar bytes, so canonically equivalent Unicode spellings remain distinct. Complete-input UTF-8 validity is checked before strict JSON grammar. `versionTuple()` exposes the pinned contract; `planCapability()` explicitly reports unavailable admission/execution authority.

## Read embedding

`KDNARead` provides admission, projection and async read operations. `KDNATrustedReadControlProvider` and `KDNATrustedHostReadProvider` are explicit embedding boundaries. The Host observer supplies the exact public Host decision, including snapshot/digest identity, scope and valid timing. Its optional async delivery callback confirms delivery only by returning `true`. Scope and policy are observed again before disclosure. Use the same snapshot and Host provider for stable expansion; serialized data cannot instantiate an attested snapshot or issuing Host registry. Projection alone does not grant permission.

## Package consumption and verification

Check out the exact Git revision you intend to consume and use a SwiftPM path dependency. Select the `KDNACore` product in your application target:

```swift
.package(path: "../kdna-core-swift")
// In the application's target dependencies:
.product(name: "KDNACore", package: "kdna-core-swift")
```

No public tag or registry release is asserted for this candidate. `public-contract-binding.json` records its contract and reference coordinates; `public-inputs.json` records the exact current source, resource and test bytes.

```sh
python3 scripts/check_public_surface.py
python3 scripts/test_public_surface.py
python3 scripts/verify_native.py --work-dir ../kdna-swift-check --ios
```

The last command requires a new directory outside the checkout. It builds the release library, runs the full XCTest suite, builds and runs an independent package that imports the public API, and compiles for a generic iOS device. Omit `--ios` for a macOS-only check. For development, `swift build` and `swift test` also work directly.

Tests include real containers, frozen Node reference observations, malformed UTF-8/JSON, canonical number spelling, mandatory support closure and Host/handle/budget/delivery scenarios. They use the bundled fixtures without a Node checkout. Run `swift test --filter ZReadScenarioTests` alone when collecting exact per-process receipt/handle IDs against its fixed Node observations; the normal suite checks semantic expectations without treating earlier test receipt counters as failures.

## Contract and authority

The candidate binding identifies `kdna.core/0.3.0`, `kdna.canonical-ir/0.2.0` and `kdna.read/0.2.0`. Container and Payload remain 0.2.0; A/C/E/P digest profiles are unchanged. The exact public source, generated resources and reference package archives are recorded in `public-contract-binding.json`. A local candidate or reference binding does not establish independent acceptance or registry availability.

`KDNACore.componentSemanticsContract()` returns the fixed public component descriptor. Method IR values contain `declaration`, `declaration_presence` and `component_interpretations`. Explicitly adopted taxonomy, candidate-set and discriminator-set content is interpreted under the pinned public definition; undeclared component content remains undeclared, and absent authored arrays remain distinguishable from declared empty arrays. Known critical carriers are valid only at their designated typed extension positions. Unknown critical extensions block interpretation; data inside an opaque extension value is not recursively treated as an extension.

Component failures expose the public reason, nullable judgment/component references, no body, and `core: valid` / `interpretation: blocked`. Structural Core failures remain distinct. Static adoption fields and their recomputable digests establish consistency only; they do not recreate a live creation context, authenticate a human or Agent, or authorize actions.

Core admission establishes technical validity. It does not establish authorship, content quality, Creation acceptance, reading permission, or action authorization. Read disclosure requires a trusted embedding provider with explicit scope, identity, time and policy observations. A caller-supplied serialized snapshot or handle does not establish authority. Expansion handles are usable only with the original process-local snapshot and issuing Host provider; reopen creates a different snapshot.

Encrypted, signed and checksum-bearing containers remain capability-unavailable where the accepted Core rejects them. Plan admission and execution are unavailable. There is no legacy loader, raw-payload fallback, asset migration or action executor. Historical files under `retired/` are kept in Git for reference, excluded from current SwiftPM targets and not bundled as runtime resources. The current README, contribution guide and security policy describe this API; dated changelog entries describe the previous loader API.

## Source and license

The official source is [aikdna/kdna-core-swift](https://github.com/aikdna/kdna-core-swift). Code is licensed under [Apache 2.0](LICENSE).
