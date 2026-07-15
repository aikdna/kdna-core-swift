# Changelog

## Unreleased

- Replace generation-specific Capsule APIs with the sole current
  `KDNARuntimeCapsule` contract and strict `kdna.runtime-capsule` wire model.
- Match the canonical JavaScript Runtime fixtures byte-for-byte for A/C/E/P,
  ConsumptionPlan, Agent Host request/receipt, and all terminal JudgmentTrace
  states.
- Validate Plan digest, task/asset identity, Runtime negotiation, A/C/E/P,
  pre-Host character budget, Host receipt correlation, terminal status, and
  exact budget evidence fail closed.
- Pin the embedded Manifest, Payload, LoadPlan, Runtime Capsule, digest
  evidence, ConsumptionPlan, Agent Host, and JudgmentTrace schemas to the
  canonical Node authority with independent SHA-256 resource locks.
- Enforce the current container and CBOR/encryption contracts without JSON
  fallback or removed checksum declarations.
- Bind verified external grants to the exact packaged asset bytes and payload
  entry path in addition to asset identity and version.
- Preserve canonical `reasoning.self_check` projections and reject removed
  payload field spellings before LoadPlan or Runtime delivery.
- Match canonical AJV date-time and URI validation boundaries and strict RFC
  8785 JSON canonicalization semantics.
- Hash binary content entries as their original bytes and retain fail-closed
  digest computation for malformed JSON.
- Keep the public Runtime and LoadPlan value graph `Sendable` under Swift 6
  complete concurrency checking.
- Correlate every Agent Host request and JudgmentTrace with the exact Plan
  projection contract, capability basis, profile, protocol, and Capsule
  versions used for negotiation.
- Require the canonical Node repository explicitly for cross-implementation
  conformance; local path discovery and symlinked fixture roots fail closed.
- Remove the superseded Trace/projector model, permissive digest wrappers,
  source-field aliases, and placeholder vectors in favor of schema-backed
  JudgmentTrace and executable current Node fixtures.
- Audit raw repository paths, source bytes, package metadata, and workflow pins
  against the canonical post-cutover token authority, with hostile gate tests.
- Reject budget limits and observed usage outside JavaScript's exact safe
  integer range before any Swift integer conversion; boundary tests cover Plan,
  Host request/receipt, and embedded JudgmentTrace evidence.
- Build the package for the generic iOS 16 device destination in CI in addition
  to the macOS SwiftPM build and test suite.
- Keep blocked Runtime negotiation issue codes byte-identical with the
  canonical Node JudgmentTrace schema and conformance fixtures.

## 0.4.0 (2026-07-13)

- Add RFC-0019 account/device external key grant parsing and verification.
- Verify Ed25519 grant signatures and all account/device/asset bindings, unwrap
  the CEK through X25519 + HKDF + AES-KW, and decrypt AES-GCM envelopes only in
  memory.
- Require a verified authorization object for account/org LoadPlan readiness;
  plain entitlement status values and password fallback are rejected.
- Add the shared JavaScript golden vector and fail-closed tamper/expiry tests.
- Require packaged `.kdna` files for Swift LoadPlan and authorized loading;
  source directories remain authoring inputs only
- Run shared authorization conformance against packaged fixtures
- Advance the pinned shared conformance commit to file-based LoadPlan goldens
- Remove an internal handoff document and local machine path from the public
  test-vector tree

## 0.3.1 (2026-07-13)
- Replace the revision-pinned Argon2 dependency with stable `Argon2Kit` 0.1.1
- Restore SwiftPM installation through stable package-version requirements
- Preserve Argon2id RFC-compatible password derivation and encrypted-asset behavior

## 0.3.0 (2026-07-13)
- Enforce the single KDNA runtime container and reject legacy distribution layouts
- Decode `payload.kdnab` and encrypted envelopes as CBOR with no JSON fallback
- Add fail-closed LoadPlan-to-Capsule loading for public and password-protected assets
- Match JavaScript Core Capsule context shapes for index, compact, scenario, and full profiles
- Align authorization behavior with the shared conformance goldens
- Add cross-language crypto vectors and current-format encrypted lifecycle coverage
- Add the candidate consumption Trace projector

## 0.2.0 (2026-05-30)
- KDNAAssetReader: native .kdna ZIP parser
- KDNAContentDigest: canonical content digest (path:sha256, excludes reports/receipt)
- KDNACrypto: SHA-256, Ed25519 signature verification, PEM extraction
- KDNATrust: actual Ed25519 verification (not just field presence check)
- manifestForDigest: strips authoring.content_digest
- Cross-platform conformance tests with golden .kdna fixtures

## 0.1.0 (2026-05-25)
- Initial release: KDNA domain types, loader, validator, router, composer, trust verifier
