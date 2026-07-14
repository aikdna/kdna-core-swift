# Changelog

## Unreleased

- Validate runtime manifests, payload profiles, and referenced load contracts
  against digest-locked copies of the canonical Node schemas; malformed nested
  values now block LoadPlan and Capsule emission instead of producing a false
  `schema_valid` trace.
- Match full AJV date-time and URI format boundaries through a Node-generated
  shared fixture, including lowercase/whitespace RFC 3339 forms and invalid
  Foundation URL edge cases.
- Preserve frozen Capsule 1 extensibility at the top level and in trace while
  retaining strict decoding for its closed signature object.
- Support generic digest evidence whose unavailable observations carry a null
  value, while continuing to reject unavailable or mismatched evidence from a
  successful Capsule 2.
- Add opt-in Runtime Capsule 2 loading with explicit A/C/E digest evidence,
  strict RFC 8785 JCS delivery digest P, successful-Capsule invariants, and a
  one-way Capsule 2 to frozen Capsule 1 adapter.
- Match the JavaScript Capsule 2 golden bytes and A/C/E/P values, preserve
  legacy domain/access/extensions only as adapter metadata, and fail closed on
  independent digest mismatches.
- Make direct Capsule 1 output byte-for-byte equivalent to the Capsule 2
  adapter, including the shared `kdna-core` loader identifier and the original
  `open`, `protected`, or `runtime` access spelling on the frozen v1 wire.
- Reject unknown Capsule properties and missing required-but-nullable fields
  during decoding, including nested signature, trace, digest, evidence,
  compatibility, and extension objects.
- Make the public Capsule and LoadPlan value graph `Sendable`, and keep the
  test suite clean under Swift 6 complete concurrency checking with warnings
  as errors.
- Order content-tree entry paths by UTF-8 bytes while retaining RFC 8785 UTF-16
  object-key ordering, and compute Capsule 1 E even without checksums.json.
- Hash non-JSON content-digest entries as their original bytes and add a
  JavaScript/Swift binary-payload conformance vector.
- Add throwing content-digest computation for fail-closed invalid JSON while
  retaining a deprecated non-throwing compatibility wrapper.
- Accept the explicit `entry_set_digest` checksum field and its metadata while
  retaining the KDNA 1.0 `asset_digest` alias; conflicting declarations are
  rejected.
- Preserve Runtime Capsule 1.0 and external grant v1 entry-set bindings while
  improving JSON string, key-order, and number canonicalization parity.

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
