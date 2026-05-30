# Changelog

## 0.2.0 (2026-05-30)
- KDNAAssetReader: native .kdna ZIP parser
- KDNAContentDigest: canonical content digest (path:sha256, excludes reports/receipt)
- KDNACrypto: SHA-256, Ed25519 signature verification, PEM extraction
- KDNATrust: actual Ed25519 verification (not just field presence check)
- manifestForDigest: strips authoring.content_digest
- Cross-platform conformance tests with golden .kdna fixtures

## 0.1.0 (2026-05-25)
- Initial release: KDNA domain types, loader, validator, router, composer, trust verifier
