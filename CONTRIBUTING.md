# Contributing to kdna-core-swift

This package implements the bounded Core and Read contracts described in the
README and `public-contract-binding.json`. The current SwiftPM graph exports
`KDNACore`, has no external package dependencies, and loads its own schema resources.

## Prerequisites and layout

Use an Apple Swift toolchain that supports the Swift 5.9 package manifest.
The package declares macOS 13 and iOS 16 deployment targets. Full verification
also needs Xcode with an iOS SDK and Python 3. CI runs on macOS; Linux is not
currently supported by the Darwin/CryptoKit implementation.

- `Sources/KDNACore/`: current native Core and Read implementation and schemas.
- `Tests/PublicCoreTests/`: XCTest assertions, real containers and frozen reference observations.
- `scripts/`: public-surface checks and native verification entry point.
- `public-inputs.json`: SHA-256 inventory of current package, source and test inputs.
- `retired/`: preserved previous implementation, fixtures and documentation, outside current targets.

## Reproduce CI locally

```sh
python3 scripts/check_public_surface.py
python3 scripts/test_public_surface.py
python3 scripts/verify_native.py --work-dir ../kdna-swift-check --ios
```

Use a new directory outside the checkout for each complete verification. The
runner builds the release library, runs all XCTest cases, creates an independent
SwiftPM consumer that imports only the public API, and compiles for a generic
iOS device without signing. It keeps build and module caches in the supplied
directory and propagates command failures. The iOS step checks compilation;
it does not establish runtime behavior on a physical device.

For a macOS-only check, omit `--ios`. During development, `swift build`,
`swift build -c release`, and `swift test` remain available. Open `Package.swift`
in Xcode to work with the library and test target.

## Contract changes

The tests compare behavior to bundled reference observations at the exact
coordinates in the binding. They do not fetch a moving reference checkout.
The supported contract includes technical container admission, strict JSON,
canonical IR and digests, component interpretation, and explicit trusted Read
embedding. Admission and projection do not establish action authorization.
Encrypted or signed capabilities, Plan admission/execution and the historical
loader are unavailable where the current API reports them unavailable.

Treat the binding, generated resources and current source/fixture inventory as
one reviewable contract change. Do not regenerate expected results or relax a
check merely to accept a divergence. Explain the supported behavior and its
reference coordinate, reproduce the failure, and include a regression case.
The public-surface gate verifies every inventory hash and the original bytes
retained under `retired/`. Naming checks classify SwiftPM deployment constants
and the historical Argon2 version by their third-party API syntax.

Changes to CI must retain the required `test` and `Analyze (swift) (swift)`
contexts, the complete native test entry point and the iOS compilation leg.
The gate's mutation tests demonstrate rejection of missing fixtures, changed
frozen bytes, a partial test suite and absent authority checks in the consumer.

Update README, CHANGELOG and security guidance when public behavior changes.
Code contributions are licensed under Apache 2.0.
