#!/usr/bin/env node
/**
 * kdna-core-swift / test-vectors / generate.js
 *
 * Generates golden test vectors for JS ↔ Swift crypto parity checks.
 * Mirrors the JS-side kdna-core@0.15.0 implementation of:
 *   - kdna-licensed-entry-v1 (HKDF + AES-256-KW + AES-256-GCM)
 *   - kdna-password-protected-v1-scrypt (scrypt + AES-256-KW + AES-256-GCM)
 *
 * Output: test-vectors/scrypt-password-v1.json (one canonical vector)
 *
 * The Swift side reads this JSON and runs the same encryption algorithm
 * via CryptoKit; the round-trip must produce identical bytes.
 *
 * Run: node test-vectors/generate.js
 */

'use strict';

const crypto = require('crypto');
const fs = require('fs');

// Load kdna-core from the local dev checkout (../../kdna/packages/kdna-core)
const path = require('path');
const KDNA_CORE = path.resolve(__dirname, '../../kdna/packages/kdna-core/src');
const {
  encryptProtectedEntryScrypt,
  decryptProtectedEntryScrypt,
  encryptLicensedEntryV1,
  decryptLicensedEntryV1,
} = require(KDNA_CORE);

// ── Deterministic inputs ────────────────────────────────────────────
// All inputs are fixed strings so the same JS output matches every run.
// Swift side hardcodes the same inputs.

const FIXTURES = {
  // Scrypt password profile (B2 v0.1 write profile, kdna-core 0.15.0)
  scrypt: {
    profile: 'kdna-password-protected-v1-scrypt',
    plaintext: JSON.stringify({
      core: { meta: { domain: 'vector-skill' } },
      axioms: [{ id: 'a1', one_sentence: 'parity check axiom' }],
    }),
    entryName: 'payload.kdnab',
    manifest: { name: 'kdna:vector:test', asset_id: 'kdna:vector:test', version: '0.1.0' },
    password: 'kdna-test-password-2026',
  },
  // RFC-0008 licensed entry v1
  licensedV1: {
    profile: 'kdna-licensed-entry-v1',
    plaintext: JSON.stringify({ core: { meta: { domain: 'vector-licensed' } } }),
    entryName: 'payload.kdnab',
    manifest: { name: 'kdna:vector:licensed', asset_id: 'kdna:vector:licensed', version: '0.1.0' },
    licenseKey: 'test-license-key-2026',
  },
};

function generate() {
  const vectors = {};

  // ── Scrypt password round-trip ──────────────────────────────────
  const scryptEnv = encryptProtectedEntryScrypt(
    FIXTURES.scrypt.plaintext,
    {
      entryName: FIXTURES.scrypt.entryName,
      manifest: FIXTURES.scrypt.manifest,
      password: FIXTURES.scrypt.password,
    },
  );
  const scryptDecrypted = decryptProtectedEntryScrypt(
    JSON.stringify(scryptEnv),
    {
      entryName: FIXTURES.scrypt.entryName,
      manifest: FIXTURES.scrypt.manifest,
      password: FIXTURES.scrypt.password,
    },
  );
  vectors.scrypt_password_v1 = {
    profile: scryptEnv.profile,
    alg: scryptEnv.alg,
    kdf: scryptEnv.kdf,
    key_wrapping: scryptEnv.key_wrapping,
    scrypt_params: scryptEnv.scrypt_params,
    key_slots: scryptEnv.key_slots,
    iv: scryptEnv.iv,
    tag: scryptEnv.tag,
    ciphertext: scryptEnv.ciphertext,
    // Decryption proof (must round-trip)
    plaintext: scryptDecrypted.toString('utf8'),
    // Failure cases
    wrong_password_fails: (() => {
      try {
        decryptProtectedEntryScrypt(
          JSON.stringify(scryptEnv),
          {
            entryName: FIXTURES.scrypt.entryName,
            manifest: FIXTURES.scrypt.manifest,
            password: 'wrong-password',
          },
        );
        return false;
      } catch {
        return true;
      }
    })(),
  };

  // ── Licensed v1 round-trip ─────────────────────────────────────
  const licEnv = encryptLicensedEntryV1(
    FIXTURES.licensedV1.plaintext,
    {
      entryName: FIXTURES.licensedV1.entryName,
      manifest: FIXTURES.licensedV1.manifest,
      licenseKey: FIXTURES.licensedV1.licenseKey,
    },
  );
  const licDecrypted = decryptLicensedEntryV1(
    JSON.stringify(licEnv),
    {
      entryName: FIXTURES.licensedV1.entryName,
      manifest: FIXTURES.licensedV1.manifest,
      licenseKey: FIXTURES.licensedV1.licenseKey,
    },
  );
  vectors.licensed_entry_v1 = {
    profile: licEnv.profile,
    alg: licEnv.alg,
    kdf: licEnv.kdf,
    key_wrapping: licEnv.key_wrapping,
    wrapped_key: licEnv.wrapped_key,
    iv: licEnv.iv,
    tag: licEnv.tag,
    ciphertext: licEnv.ciphertext,
    plaintext: licDecrypted.toString('utf8'),
  };

  return {
    version: 1,
    generated_at: new Date('2026-06-27T00:00:00Z').toISOString(),
    kdna_core_version: '0.15.0',
    note: 'JSON-stable fixtures. Timestamps are pinned so the file is diff-stable.',
    vectors,
  };
}

const out = generate();
const outPath = path.join(__dirname, 'golden-v1.json');
fs.writeFileSync(outPath, JSON.stringify(out, null, 2) + '\n');
console.log('Wrote', outPath);
console.log('  scrypt_password_v1:');
console.log('    profile:', out.vectors.scrypt_password_v1.profile);
console.log('    kdf:', out.vectors.scrypt_password_v1.kdf);
console.log('    scrypt_params:', JSON.stringify(out.vectors.scrypt_password_v1.scrypt_params));
console.log('    round-trip OK:', out.vectors.scrypt_password_v1.plaintext.length, 'bytes');
console.log('    wrong-password fails:', out.vectors.scrypt_password_v1.wrong_password_fails);
console.log('  licensed_entry_v1:');
console.log('    round-trip OK:', out.vectors.licensed_entry_v1.plaintext.length, 'bytes');
