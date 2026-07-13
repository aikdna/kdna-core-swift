# Changelog

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
