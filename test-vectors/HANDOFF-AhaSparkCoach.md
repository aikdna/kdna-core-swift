# Swift Golden Vectors — handoff to AhaSparkCoach

This package is ready for cross-language parity verification between
JS-side `@aikdna/kdna-core@0.15.0` and Swift-side KDNACore.

## Files

- `test-vectors/generate.js` — JS-side generator. Run with
  `node test-vectors/generate.js` (requires `../../kdna/packages/kdna-core`
  checkout). Writes `test-vectors/golden-v1.json`.
- `test-vectors/golden-v1.json` — pinned fixture, **1.6 KB**,
  contains:
  - `vectors.scrypt_password_v1` — full envelope (profile, scrypt_params,
    key_slots, iv, tag, ciphertext, plaintext, wrong_password_fails).
  - `vectors.licensed_entry_v1` — full envelope (profile, alg, kdf,
    wrapped_key, iv, tag, ciphertext, plaintext).
- `Tests/KDNACoreTests/GoldenVectorsTests.swift` — placeholder test
  that loads the JSON fixture and asserts structural fields. Two
  commented-out parity tests are ready to be uncommented when Swift
  B2/B6 land.
- `Tests/KDNACoreTests/Fixtures/golden-v1.json` — bundle copy.

## What AhaSparkCoach needs to do

1. **Swift B2 (kdna-password-protected-v1-scrypt)**: implement
   `KDNACoreSwift.encryptProtectedEntryScrypt(plaintext, entryName,
   manifest, password)` and matching `decryptProtectedEntryScrypt`
   using CryptoKit:
   - `CryptoKit.SHA256` + scrypt-style KDF (CryptoKit has no native
     scrypt → use CommonCrypto's `CCKeyDerivationPBKDF` or
     `CCCalibratePBKDF` from the `CommonCrypto` module)
   - `CryptoKit.HMAC<SHA256>.HKDF` for CEK wrapping
   - `CryptoKit.AES.GCM.seal/open` for content encryption
   - Per RFC-0009 §4: salt 16 random bytes, N=32768, r=8, p=1,
     KEK output 32 bytes, CEK 32 bytes random, IV 12 bytes random.

   When implemented, uncomment `testScryptRoundTripParity()` in
   `GoldenVectorsTests.swift` and verify the Swift-side decryption
   returns the same plaintext that JS produced.

2. **Swift B6 (License verifySignature)**: ADR-005 §5 requires real
   Ed25519 verification (or explicit `unsupported` / `denied`).
   Currently `KDNALicenseTypes.verifySignature` throws
   `KDNAError.unsupportedProfile`. The fix path:
   - Use `CryptoKit.Curve25519.Signing.PublicKey` for Ed25519.
   - The license signature field stores `ed25519:<base64>` per the
     v0.3 strategy doc §7.2.
   - Add a JS-side test vector (license fixture + sign with
     `crypto.sign` ed25519) to `generate.js` so Swift can verify
     parity.

3. **Run on macOS**:
   ```sh
   cd /Users/AI/K/OPEN/kdna-core-swift
   swift test --filter GoldenVectorsTests
   ```

## Non-goals

- Do NOT implement kdna-password-protected-v1 (Argon2id) — that's
  v0.2 (post-B2). v0.1 is scrypt only.
- Do NOT regenerate `golden-v1.json` from Swift; the JS side is the
  source of truth for cross-language parity.

## Status

- 2026-06-27: JS-side generator + fixture + Swift-side placeholder
  test pushed (no real Swift implementation yet).
- AhaSparkCoach to do Swift B2 + B6 + verify on macOS.
