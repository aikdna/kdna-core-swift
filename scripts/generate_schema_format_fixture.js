#!/usr/bin/env node
'use strict';

// Regenerate the committed format fixture from the exact AJV implementation
// used by the canonical Node repository. This script prints JSON to stdout so
// a review can inspect the evidence before replacing the fixture.
const path = require('node:path');
const root = process.env.KDNA_CONFORMANCE_ROOT || path.resolve(__dirname, '../../kdna');
const Ajv = require(path.join(root, 'node_modules/ajv/dist/2020'));
const addFormats = require(path.join(root, 'node_modules/ajv-formats'));

const candidates = {
  'date-time': [
    '2026-07-15T12:34:56Z',
    '2026-07-15t12:34:56z',
    '2026-07-15 12:34:56+23:59',
    '2000-02-29T23:59:60Z',
    '2025-02-29T12:00:00Z',
    '2026-07-15T12:34:56',
    '2026-07-15T12:34:56Ztrailing',
    '2026-07-15T24:00:00Z',
    '2026-07-15\u008512:34:56Z',
    '2026-07-15\uFEFF12:34:56Z',
    '2026-07-15ſ12:34:56Z',
    '2026-07-15K12:34:56Z',
  ],
  uri: [
    'urn:uuid:00190000-0000-4000-8000-000000000001',
    'https://example.com/a?b#c',
    'mailto:test@example.com',
    'a:',
    'a: x',
    'relative/path',
    'https://exa mple.com',
    'urn:%zz',
    'https://example.com:１２/path',
    'https://example.com:١٢/path',
    'Kttps://example.com',
    'https://example.Kom',
    'ſttps://example.com',
  ],
};

const ajv = new Ajv({ strict: true });
addFormats(ajv);
const output = {
  generator: 'scripts/generate_schema_format_fixture.js',
  canonical_commit: '76bbc587ce05f7e575c2373832cc5c9eee9df98a',
  ajv_formats: '3.0.1',
};
for (const [format, values] of Object.entries(candidates)) {
  const validate = ajv.compile({ type: 'string', format });
  output[format] = values.map((value) => ({ value, valid: validate(value) }));
}
const rendered = JSON.stringify(output, null, 2)
  .replaceAll('\u0085', '\\u0085')
  .replaceAll('\uFEFF', '\\uFEFF');
process.stdout.write(`${rendered}\n`);
