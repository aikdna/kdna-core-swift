# Sections read-chain port (container 0.6.0) — design note

> Branch: `claude/sections-read-chain` (local only; the repo is under the
> recovery-period push seal — publication waits for the Owner gate and the
> joint unfreeze). Prepared by the Render refoundation session (kdna-a8) from
> a byte-level study of the Node reference implementation; alignment points
> with the open-line sessions (kdna-c0 / kdna-f2) are recorded at the end.

> **Candidate-state mirroring (f2 early-alignment requirement):** the
> sections chain is a candidate-only sub-surface inside the stable packages
> (`contract.candidate_only: true`, module
> `kdna.representation06.candidate-a15-05`). This port's public narration,
> docs headers and contract identity fields MUST mirror that state — no
> names, type names or prose may mint a "stable" feel for this surface.
> Type names keep the `KDNA*` prefix; candidate status lives in doc
> comments and identity fields, never in type names.

## 1. Why

A real consumer needs it: the coach product ships the re-authored
current-format coach bundles (`kdna.json` + `sections/pack-*.kdnab`,
container 0.6.0) but its on-device KDNA reader (`KDNACore`, pinned at
fbb6e45; open-line HEAD 0b85375 matches) parses only the retired layout
(`kdna.json` + `payload.kdnab`). Measured: `swift test --filter
KDNALoaderServiceTests` fails 5/5 with `KDNA_FORMAT_INVALID — not a KDNA
runtime asset`. The port is demand-driven and intended to be borrowable by
the open line: the container/read semantics are ecosystem infrastructure.

## 2. Baseline coordinates (verified 2026-10-06)

- Released artifacts (npm): `@aikdna/kdna-core` 0.36.0 (tarball sha256
  `11f6f00c…`) and `@aikdna/kdna-read` 0.11.0 (tarball sha256 `40508da8…`).
  The Render side content-verified the promotion (identical sections
  contract tuple; mechanical-only code differences from the rc pins).
- Sections chain tuple (10 fields, from `sections/contract.json` +
  consumer probe): `container 0.6.0`; `payload_profile
  kdna.payload.judgment`; `payload_version 0.5.1`; `core kdna.core/0.8.2`;
  `ir kdna.canonical-ir/0.6.1`; `runtime kdna.runtime-capsule/0.3.1`; `plan
  kdna.consumption-plan/0.3.1`; `host kdna.agent-host/0.3.1`; `trace
  kdna.judgment-trace/0.3.1`; `read kdna.read/0.7.0-candidate` (retained
  contract `kdna.retained-sections/0.1.0-candidate`, 4 modes).
- Important divergence to keep in view: the sections chain is a
  candidate-only sub-surface inside the stable packages
  (`sections/contract.json` is `candidate_only: true`, module
  `kdna.representation06.candidate-a15-05`). Container 0.5.0 /
  `read 0.6.4` (the `admitNode` path) coexists in the same packages and is
  NOT the port target.
- Contract identity fields carried by the port's decoded views must keep
  the candidate module id (`kdna.representation06.candidate-a15-05`) and
  the tuple verbatim; any public doc for the port repeats the
  candidate-only state.
- There is no standalone spec document and no conformance fixture for the
  sections chain in the open repo; the normative sources are
  `packages/kdna-core/src/public-contract/sections/contract.json`
  (embedded prose keys) plus the implementation family quoted below. This
  port's golden fixtures will be generated from the Node chain — the first
  cross-implementation conformance vectors for this surface.

## 3. Format facts (each re-verifiable; paths under `open/kdna/`)

### 3.1 Container

- Entries (closed): `mimetype` (entry 0, local offset 0, method 0, exact
  value `application/vnd.kdna.asset`), `kdna.json`, optional
  `checksums.json` / `signature.kdsig`, `sections/pack-N.kdnab` (no leading
  zero unless N=0), `attachments/…`. `payload.kdnab` rejects.
  (`section-container.js`, `section-capture-node.js`)
- ZIP subset: EOCD last-signature rule with forward-routing locator, no
  fallback; ≤128 entries; ≤25 MiB total, ≤8 MiB entry; contiguous
  gap-free local regions; `sections/*` must be method 0; other entries
  method 0/8; CRC32 both header copies; flags only `0x800`; no ZIP64/
  multi-disk/data-descriptors/encryption. Limits: ratio ≤100.
- `kdna.json`: `Manifest06Candidate`, closed, `format_version` const
  `0.6.0`; `payload` is `SectionPayloadDescriptor06` (`layout:"sections"`,
  `encoding:"strict-cbor-frames"`, `tables` ≥3 rows,
  `xref_codec:"frame-local-ordered-scope-dictionary/1"`);
  `representation_metadata` is the `node-order-index/1` codec (see 3.3).

### 3.2 Packs and frames

- A pack is a bare concatenation of CBOR frames; the only index is
  `kdna.json`’s `payload.tables` plus three table frame families.
- Frame kinds: `xref:<ordinal>:<chunk>` (`chunk = i/1024`), `topic:
  <judgment_id>`, `volume:<floor(i/512)>`, and the tables
  `table:sections:<part>` / `table:topics:<part>` /
  `table:node_sections:<part>` (4096 rows/part).
- CBOR quirks (cbor-x with `useRecords:false, mapsAsObjects:true,
  alwaysUseFloat:true`): **every map (even 1-key) starts `0xb9` + 2-byte
  count; every number is `0xfb` + float64 BE.** Arrays/texts use normal
  CBOR headers. Decoding is two-phase strict (hand walk + cbor-x decode
  with JSON key-order equality): no byte strings, no tags, no indefinite
  lengths, unique string keys, depth ≤64, ≤10000 items, text ≤1 MiB,
  finite floats, integers exactly representable as binary64, no trailing
  bytes. (`cbor.js`)
- Frame order is positional, not sortable: `xref:0:*`, then per catalog
  item `topic:<jid>` + `xref:<i+1>:*`, then `volume:*` in unsigned-UTF-8
  `node.id` order, then tables in order `sections, topics, node_sections`.
  Pack membership: `pack-<floor(ordinal/8)>`; offsets contiguous within a
  pack and restart at 0. (`source-route-frame-writer.js`,
  `section-frame-graph.js`, `section-layout.js`)
- Reader re-derivation enforces the identity graph (closed codes:
  `CATALOG_DUPLICATE`, `CLOSURE_*`, `TABLE_*`, `KEY_ORDER_OR_DUPLICATE`,
  `NODE_MAP_*`, `TOPIC_*`, `VOLUME_*`, `FRAME_*`, `SECTION_COVERAGE`,
  `PACK_*`, `DUPLICATE_RECORD`, …) — see §2.4 of the implementation study
  for the exhaustive list.

### 3.3 Metadata codec

`representation_metadata` (public) is stored deduplicated
(`node-order-index/1`): `references[].source_node/target_node` →
`source_node_index/target_node_index` (indices into `node_order`),
`asset_index[].node_ref` → `node_index`, `mandatory_closures[].node_ids[]`
→ `node_indices[]`, `asset_closure[]` → indices; `codec` key deleted on
decode/re-added on encode; index range/id-missing dup checks
(`METADATA_*`). `node_order` is the identity spine compared positionally
(`section-metadata-codec.js`, `section-partition-bindings.js`).

### 3.4 Digests

- **A** = raw final container bytes (no normalization; includes the ZIP
  comment). **C** = content tree with the `KDNA-CONTENT-TREE\0 0.2.0\0`
  preimage; names excluded (`checksums.json`, `signature.kdsig`), `*.json`
  strict-parsed and JCS-canonicalized, and **in `kdna.json` only**
  `content_digest` / `authoring.content_digest` deleted; every other entry
  contributes raw bytes (packs included). **E** = runtime entry set,
  `0.3.0-candidate` (`KDNA-RUNTIME-ENTRY-SET\0`), names = unique-sort(
  `kdna.json` + actual packs + `runtime.mandatory_entries`) — note this is
  a 0.6-specific variant (`section-digests.js:observeE`), not the 0.5
  `runtimeEntryPreimage`.
- IR digest = `digestCanonical({...buildIR(...), tuple})`, cross-checked
  against the IR restored from frames — `SECTION_DERIVED_IR_MISMATCH` is
  the chain's most important verification.
- `checksums.json` doc/2 (scoped verification strength distinction) and
  `signature.kdsig` (`kdsig.ed25519/0.1.0`, Ed25519 over a row-hash
  preimage) are optional surfaces with their own closed semantics.

### 3.5 Faces, opaque tokens, diagnostics

- Faces in order: `admitSectionRequest` (closed 6-key request, 4 modes) →
  capture/retain → `whole|catalog|exact_selection|expand` snapshots →
  byte routing (`sections-bytes-node.js`) → retained faces in
  `kdna-read` (`admitRetainedSectionRequest`,
  `createRetainedSectionReadAuthority`, `prepareRetainedSectionRead`,
  `readRetainedSection`).
- Opaque values (request/authority/snapshot/handle/witness) are
  schema-`false` brands, WeakMap-keyed, same-instance only: **a Swift port
  substitutes its own opaque handle types** (final classes, internal
  registries); they can never round-trip through JSON.
- The four phases (input → metadata → authorization → content/semantic)
  are observable (`stage` in rejections); the authorize callback runs
  before any pack body read and must return literal `true`;
  `wholeAfterAuthorization` is a one-shot latch.
- Closed diagnostic sets: 8 admission-unsupported reasons, 13
  `RetainedSectionDetail06` values, the 44-code ReadDiagnosticCode list,
  the CoreComponentFailure codes, and the `SECTION_*` family — all quoted
  verbatim in the implementation study; the port must carry them
  unchanged (named differences only, per the review discipline).

### 3.6 Existing primitives inventory (recon of this repo, 2026-10-06)

The package already carries, oracle-tested, most of the stack the port
needs — the real delta is the 0.6 container/semantic layer:

- `PublicCBOR` (PublicContainer.swift) already implements the strict CBOR
  walk the 0.6 frames require: depth/item caps, exactly-representable
  integers (incl. the -1-n 2^64 edge), byte-string rejection, text caps +
  scalar checks, unique string keys, indefinite-length rejection, finite
  floats (half/single/double), trailing-byte rejection. Frames can decode
  through it unchanged (object key order is not load-bearing on the Swift
  side: JCS sorts, the frame shapers check key sets, and there is no second
  decoder to cross-check order against).
- `KDNAJSON.canonical` + `numberText` (PublicValues.swift) implement JCS
  with ECMAScript number spelling, covered by a 2066-row Node oracle
  (`Fixtures/number-oracle.json`) — no duplicate JCS layer is needed (an
  initial duplicate was written and removed on this branch).
- `PublicContainer.parse` (strict ZIP subset with hand-rolled inflate +
  CRC), `PublicDigests`, and the schema-admission machinery exist for the
  0.2.0/0.5.0 lines; the 0.6 work is to parameterize the container rules
  (entry allowlist incl. `sections/pack-N.kdnab`, stored-method rule for
  packs, no `payload.kdnab`) and to add the sections layer on top.
- Fixture tradition: per-key `.kdna` fixtures plus oracle JSON files under
  `Tests/PublicCoreTests/Fixtures` (e.g. `component-node-oracles.json`,
  `number-oracle.json`) — the sections goldens follow this pattern.

Delta inventory for 0.6 (the actual port scope):
1. Container rules variant (allowlist, pack stored-method, limits).
2. `kdna.json` 0.6 manifest view + closed validation (payload descriptor,
   representation_metadata pass-through).
3. Frame graph: pack concatenation walk, xref/topic/volume/tables, the
   identity graph and its closed `SECTION_*` codes.
4. `node-order-index/1` metadata decode.
5. Digests: A (same idea), C (same preimage strings; 0.6 exclusions +
   kdna.json `content_digest`/`authoring.content_digest` deletion), E
   (`observeE`, `0.3.0-candidate` variant), IR digest + `buildIR` cross-check.
6. Faces: admission/snapshot/modes/bytes (+ retained faces) with the
   opaque-token discipline.

## 4. Swift architecture

New within `Sources/KDNACore` (additive; keep existing public surfaces;
reuse `PublicCBOR`, `KDNAJSON.canonical`, `PublicContainer` machinery):
`Sections/SectionContainer.swift` (0.6 container rules variant),
`Sections/SectionContract.swift` (loaded SHA-pinned contract + generic
validate), `Sections/SectionManifest.swift` (0.6 manifest view + closed
validation), `Sections/FrameGraph.swift`,
`Sections/MetadataCodec.swift`, `Sections/SectionDigests.swift` (A/C/E +
IR), `Sections/SectionFaces.swift` (admission/snapshot/modes/bytes),
`Sections/RetainedRead.swift`, `Sections/Diagnostics.swift` (closed code
enums). Tokens become opaque final classes with a registry mirroring the
WeakMap discipline. TOCTOU: where file-based reads are used, re-check a
stat key before/after every read as the Node fd capture does; the initial
port may operate on in-memory bytes (the consumer loads bundle resources),
which keeps the discipline trivially but must keep the same phase order.

Confirmed surface decisions (f2 + c0 early-alignment, binding):

- Naming: keep the `KDNA*` prefix (repo convention; the naming gate bans
  only V+integer generation labels); run a collision sweep against existing
  type names before landing; candidate state in docs/headers only.
- Faces: **asset-hung** (f2's preference governs; c0's free-function note
  is compatibility context only). The binding criterion is payload
  discipline — the phase tokens (admitted request / authority / prepared /
  snapshot) are the only channel through phases and are always mandatory
  parameters; phase order, the one-shot latch and stage observability match
  the Node implementation point-by-point. The retained prepare keeps the
  Node semantics (snapshot leading among its arguments, three arguments in
  total) while hanging on the asset object; naming maps 1:1 to the Node
  faces for review.
- Authority callback: a Swift closure returning `Bool?`; only `.some(true)`
  grants (`.none` / `.some(false)` / thrown errors all deny — equivalent to
  Node's strict `!== true`, which rejects every truthy non-true). Node
  facts: the callback is awaited (async), invoked before any pack body byte
  is read, the signature policy is validated and carried into the context,
  and the prepared token is one-shot. Creating an authority from a
  non-function throws `RETAINED_AUTHORITY_CALLBACK`. The document states
  plainly that observation is not authority ("观测≠权威").

Ordering rules that MUST NOT be unified: JCS key order = UTF-16 code-unit
(ECMAScript); EntryName/node-id/table-key order = unsigned UTF-8 bytes.

## 5. Staged plan

- **Stage A (unblocks the real consumer):** open container → validate
  ZIP subset + manifest → whole read → A/C/E + IR cross-check → judgment
  supply projection (nodes with conditions/boundaries as the Render
  adapter surfaces them). Acceptance: the consumer's loader tests green
  plus digest equality against Node golden fixtures for the four coach
  bundles.
- **Stage B (parity):** catalog / exact_selection / expand faces, frame
  graph re-derivation with the closed codes, retained faces + host-gate
  semantics, byte routing. Acceptance: member-level byte comparison of
  every frame + decoded structures against Node outputs; hostile-vector
  suite ported from the implementation study.
- **Stage C (optional surfaces):** checksums.json scoped verification,
  signature.kdsig, protection binding — closed as `unsupported` exactly
  where the Node chain closes them, until implemented.

### 5.1 Stage A progress (append-only)

**Container rules variant — landed 2026-10-06.**
`Sources/KDNACore/Sections/SectionContainer.swift` (`SectionContainer.parse`,
sibling to `PublicContainer.parse`) + parameterized
`PublicContainer.decompress(_:maximum:)` (default unchanged). Rules and
observable diagnostics mirror `@aikdna/kdna-core@0.36.0`
`src/public-contract/section-container.js`; byte-identical file verified
between the released vendored tree and the work tree before porting.
Decisions recorded while porting:

- Diagnostic mapping (matches the Node catch-all in `sections-node.js` /
  `creation-sections-node.js`): structural rule violations reject
  `READ_CORE_INVALID`; raw-decoder failures classify as
  `READ_CORE_CAPABILITY_UNAVAILABLE` — invalid UTF-8 in an entry name,
  invalid UTF-8 in the mimetype value, an inflate failure or its 8 MiB
  output cap, and an unknown compression method. A hostile fixture pins
  each.
- `kdna.json` presence is checked, not emptiness: an empty entry is
  admitted at container level, exactly as the Node truthiness check admits
  it (pinned by test).
- The `sections/pack-(0|[1-9][0-9]*).kdnab` rule is hand-rolled, not
  regex: the digit run is unbounded (must not route through `Int`), and
  the rule should not depend on ICU-versus-ECMAScript `$` anchor semantics
  across platforms (probed equivalent on this platform; hand-rolled is
  exact by construction).
- Bounds checks stay per-field `READ_CORE_INVALID` via the shared `demand`
  helper; `mode` semantics (`0` or `S_IFREG`) and the first-entry rule
  (`mimetype`, local offset 0, stored) are ported point-by-point.

**Parity evidence (scratch, released-artifact baseline).** The port was
cross-checked against the released `@aikdna/kdna-core@0.36.0`
`parseSectionContainer` on 341 synthetic containers (allowlist/naming
edges, EOCD comment, gaps, duplicate names, flag/mode/CRC/size-lie
variants, method 8/9, UTF-8 hostility cases, count 0/129, truncation,
trailing bytes, plus 300 seeded byte-level fuzz mutations of one valid
container): **zero mismatches** — 18 accepted with identical entry names,
sizes, modes and per-entry byte hashes; 309 `READ_CORE_INVALID`; 14
`READ_CORE_CAPABILITY_UNAVAILABLE`. The harness is scratch-only (case
builder + verdict dumps on both sides) and pins the released version.
No real coach material is involved anywhere; fixtures are synthetic.

Committed tests: 11 XCTest cases
(`Tests/PublicCoreTests/SectionContainerTests.swift`) with an in-code
canonical-shape container builder; full Swift suite 20/20 green.

**Manifest view — landed 2026-10-06.**
`Sources/KDNACore/Sections/SectionManifest.swift` loads kdna.json as strict
JSON and validates it closed against `Manifest06Candidate`, the way
section-common.js `validate` does: schema shape first (`SECTION_TYPED_SHAPE`
verbatim), then the scalar pass (Identifier / EntryName /
RuntimeMandatoryEntryName / Timestamp → `READ_CORE_INVALID`). The sections
contract is carried as a mechanical SHA-pinned mirror
(`Resources/Schemas/sections-contract.json`, byte-identical to the released
`@aikdna/kdna-core@0.36.0` file, `resourceSHA` pinned, every type
keyword-checked at load). The schema engine gained the `else` keyword
(draft-2020-12 if/then/else; the contract uses it outside the manifest
closure) and the manifest-view projections the downstream stages name:
`representationMetadata`, `payloadTables`, `runtimeMandatoryEntries`,
`protectionDeclared`, `assetIdentity`, `declaredContentDigests`.

Two findings while porting (both now pinned by oracle rows):

- **Ajv compiles patterns with the `u` flag** (`unicodeRegExp` default when
  the pattern is valid under `u`), so ECMAScript pattern semantics here are
  code-point based — the ICU engine agrees. A bare-regex probe without the
  flag suggested the opposite (emoji rejected as surrogate halves); the
  released validator accepted emoji identifiers and the oracle corrected the
  probe. Lesson recorded: pattern probes must reproduce Ajv's compile
  options, not just `RegExp` defaults.
- **Parse-failure classification splits in Node.** parseJson's own scanner
  rejects throw coded errors (`READ_INPUT_INVALID`), but malformed escapes
  and short `\u` hex runs surface as raw `JSON.parse` SyntaxErrors and the
  sections catch-all maps them to `READ_CORE_CAPABILITY_UNAVAILABLE` (the
  0.2/0.5 admission maps raw errors to `READ_CORE_INVALID` instead — it
  normalizes everything through its `allowed` list). The shared parser now
  distinguishes that class (`StrictJSONSyntaxFailure`) and scans exactly
  like parseJson — blind one-character escape skip, decode of the token
  body afterwards — so each line classifies exactly as its Node
  counterpart. This fix is shared; the 0.2/0.5 line's observable codes are
  unchanged.

**Manifest parity (scratch, released-artifact baseline).** 449 cases (49
curated: required/const/enum/additionalProperties/pattern/minItems/type/
if-then/uniqueItems/scalar violations, calendar-invalid timestamps,
protection markers, engine-sensitive identifier and pack-name vectors, and
raw-text parse cases incl. duplicate keys, non-finite numbers, BOM, bad
escapes, short unicode escapes, lone and paired surrogates, truncation;
plus 400 seeded text-fuzz mutations of the base): **zero mismatches**
against the released chain's verdicts. The checked-in fixture
(`Fixtures/manifest-06-oracles.json`, 99 rows: the curated set plus a
deterministic fuzz sample) records that authority in its header fields;
its rows are the committed regression. Full Swift suite 24/24 green.

**Frame decode layer — landed 2026-10-06.**
`Sections/SectionContract.swift` (the loaded SHA-pinned contract plus the
generic `validate`), `Sections/MetadataCodec.swift`
(node-order-index/1 decode: *_index fields resolve through node_order, then
validate as RepresentationMetadata06; METADATA_* codes verbatim) and
`Sections/FrameGraph.swift` (`SectionScopeCodec.decodeFrame` for
frame-local-ordered-scope-dictionary/1, then `restoreWholeFrames`: pack
concatenation walk, the three table directories, the identity graph,
xref/topic/volume ordering and every closed code ported point-by-point).
`SectionManifest` now delegates to `SectionContract`. The scope-codec
duplicate identity is `JSON.stringify(scope)` in Node; scope is an array of
Identifier strings, for which JSON.stringify equals canonical JSON — the
canonical-key check here is exact, not an approximation. The Node
double-decode equality (raw walk vs cbor-x) has no Swift analogue (single
decoder); recorded as a named difference with no observed behavioral gap.

**Frame-graph parity (scratch, released-artifact baseline).** All eight
sections assets on this machine — the four synthetic render fixtures and
the four coach bundles (local-only, never committed) — parsed by both
chains end to end: the canonical JSON of `{ir, checked_sections,
pack_names, source_ir_digest_claim, source_runtime_entry_names}` is
**byte-identical** (187–200 IR nodes, 689–1398 expansion targets, 17–25
checked sections per asset), in debug and release builds. Release timing
0.7–1.9 s per asset (debug 10–17 s; the loader builds release). The
per-asset IR digest chain (C/E + IR cross-check) remains the next package,
together with the committed frame-graph fixture: a small synthetic sections
asset produced through the released creation path, checked in with its
authored inputs and regeneration script (pinned to released 0.36.0) — the
fixture package for §7.

**Engine findings fixed while porting** (all three align Swift with the
released source; old-line oracles stay green):

- **Capacity is the payload's byte length, not a visit counter.** The Swift
  parser/canonicalizer/CBOR walk still carried `count <= 100000` limits
  that the released chain removed as the "count visits instead of measuring
  the payload" defect; real manifests exceed 100 000 values, which the
  Swift side rejected as READ_INPUT_INVALID (7 of 8 assets failed before
  the fix). Removed; the CBOR walk gained the 8 MiB input cap that
  decodePayload applies.
- **`$` anchors:** ECMAScript `$` (no multiline flag) is the absolute end
  of input; ICU's `$` also matches before a final line terminator. The
  schema engine now rewrites unescaped, non-class `$` to `\z` before
  compiling (probed against both engines on the contract's pattern shapes,
  including the EntryName lookahead construction), keeps a compiled-pattern
  cache (Ajv compiles once per schema; per-call compilation dominated the
  walk) and has a string-array fast path for `uniqueItems`.
- Together these took one asset's walk from ~22 s to ~1 s (release) with
  identical verdicts.

Committed tests: `SectionCodecTests` with three oracle fixtures —
`metadata-codec-oracles.json` (11 rows), `scope-codec-oracles.json`
(8 rows: duplicate/order/ref/unused/shape), `cbor-frame-oracles.json`
(39 rows: integer edges incl. the ±2^64 boundaries, text/control/astral,
map-16/float16 forms, caps, tags, trailing bytes). All synthetic; the
authority string on each fixture names the released files.

**Digest layer — landed 2026-10-06.**
`Sections/SectionDigests.swift`: `observeWhole` (A = container bytes;
C = the shared content-tree preimage, reusing the existing
`PublicDigests.content` port — its byte parity with digests.js is
demonstrated by the eight-asset C match below; E = `observeE` on the
kdna.digest-basis.runtime-entry-set/0.3.0-candidate profile with
SECTION_E_PACK_COVERAGE / SECTION_RUNTIME_DECLARATION /
SECTION_RUNTIME_MEMBER_MISSING verbatim), `assertContentBindings`, and
`reconstructPayload` (validates CanonicalIR06Candidate against the sections
contract, rebuilds the 0.5.1 payload shape, SECTION_ASSET_NODE /
SECTION_FORM_INVALID verbatim).

**Digest parity (scratch, released-artifact baseline).** On all eight
sections assets, A, C, E (digest + member names + profile) and the
`reconstructPayload` output digest are byte-identical to the released
chain. Committed: `sections-digests-oracles.json` (11 E rows + 5 C rows,
synthetic entry sets; the C rows also pin the checksums.json/signature.kdsig
exclusion and canonical key-order insensitivity) with
`SectionDigestsTests`.

**Discovery — the payload/IR semantic generation gap (major, re-scopes
Stage A).** The two visible failures on the eight assets were
`validate('Payload')` and `buildIR` against the package's bundled
old-line contract — and the diagnosis is structural, not a bug: the
bundled `generated-contract.json` is the **0.2.0 generation** (275 types,
tuple container 0.2.0 / payload_version 0.2.0), while the released
0.36.0 core's contract is the **0.5.0/0.5.1 generation** (431 types,
adds `r2_semantics`, `core_terms`, `static_policy`, `authoring_workflow`).
The 0.5.1 payload carries collections the 0.2 contract does not know
(contracts, conditions, shared_declarations, examples, exceptions,
misuse, asset_capability, kernel, reading_order) and richer boundary
bodies (applies_to, exception_refs) — exactly the additionalProperties
violations Ajv reports when the reconstructed payload is checked against
the bundled contract. The sections chain's semantics are the 0.5.x
generation; the Swift old-line semantic code (PublicIR 172 +
PublicComponents 231 lines) implements the 0.2 generation and is not a
substitute. Consequently:

- **Stage A1 (done):** container, manifest, frame graph, codecs, digests
  A/C/E, reconstruct — all parity-verified on the eight local assets.
- **Stage A2 (new workstream, on the critical path for the IR
  cross-check):** vendor the released generated-contract.json (sha256
  b405bdb007ce18e144c607d92af4127540119c6d302724c313ae6bb0b72ab915) as a
  second SHA-pinned resource and port the 0.5 semantic generation:
  r2-registry (105 lines), r2-values (90), r2-semantics (316),
  component-semantics (191), static-policy-semantics (52), cross-entry
  (462), canonical-ir (97) — roughly 1 300 dense lines against the 0.5
  contract, with acceptance = derived-IR digest equals the restored-IR
  digest on the eight assets plus the Node-side hostile suites for those
  modules. `SectionDigests.reconstructPayload` and the frame graph are
  already generation-independent and stay as landed.
  - **A2a (landed 2026-10-06):** the 0.5 contract is vendored as
    `Resources/Schemas/generated-contract-0.5.json` (byte-identical to the
    released file; SHA-pinned; its keyword set is fully inside the schema
    engine, so no engine extension was needed) with
    `Sections/SemanticContract.swift` (`validate("Payload", …)` and the
    same surface `validate.js` drives: shape first, then the scalar pass).
    Parity: for all eight local assets the reconstructed payload validates
    `ok` exactly as in Node, and seven named mutations per asset (56 cells:
    missing/invalid asset, unknown top-level and nested fields, wrong
    profile_version, emptied judgments) all classify `READ_CORE_INVALID` on
    both sides — zero mismatches. Committed `SemanticContractTests`
    (resource pin + tuple + type counts + negative rows + the deliberate
    two-generation coexistence assertion).
    Named difference (recorded): the Node rejection carries an Ajv field
    pointer (diagnostic.field); this port reports the code without the
    pointer until a consumer needs it. Synthetic-positive payload rows are
    deferred to the fixture package (the created synthetic asset's payload
    will serve as the committed positive instance).
  - **A2b (landed 2026-10-06):** `Semantics/R2Registry.swift` (typed
    targets, ownership, mandatory/optional edges, reference roles,
    unresolved externals, mandatory closure) and
    `Semantics/R2Values.swift` (contracts, shapes, result values,
    projections, compatibility, binding completeness). `PublicFailure` now
    carries the registry/values `field` and `subject` diagnostics verbatim.
    Parity: the full registry state for all eight local assets — ordered
    records with targets/owners/paths/activations/value digests, unresolved
    edges, reference roles and every closure — is **byte-identical** (766 KB
    of canonical JSON) to the released `createRegistry`. Committed
    `r2values-oracles.json` (44 synthetic rows across all eleven helpers)
    with `R2ValuesTests`. Two porting facts pinned: the registry identity
    key is the canonical array `[asset|null, kind, id]` (not the ref
    object), and JS Map insertion order is observable (reference roles
    iterate into the derived IR's reference array), so the port carries
    insertion-ordered maps; `bounds` distinguishes an absent `maximum` from
    an explicit null (JS `=== null`).
  - **A2c part 1 (landed 2026-10-06):** `Semantics/ComponentSemantics.swift`
    (carrier registry and profiles from the contract, definition-digest
    integrity, extension walking, method presence/adoption carriers,
    component declarations with every digest binding and limit) and
    `Semantics/StaticPolicySemantics.swift` (the single critical carrier,
    rule digest, priority normalization, candidate validation). Parity: the
    full `resolveComponents` / `resolveStaticPolicies` /
    `checkInterpretationComplete` output on all eight local assets is
    byte-identical (238 KB canonical JSON). The eight assets carry no
    static-policy carriers, so the policy success path was exercised with a
    crafted synthetic payload in scratch (recorded: the supported record is
    byte-identical to Node's, 1.8 KB canonical); promoting it to a
    committed fixture rides on the fixture package. Committed
    `visit-extensions-oracles.json` (7 synthetic micro-payload rows with
    verbatim traversal paths and the two interpretation-complete verdicts)
    with `ComponentSemanticsTests`. Porting facts pinned: the JS `\w` gate
    in item keys is implied by the ASCII key grammar (ICU `\w` is
    Unicode-aware, JS's is not); the utf8()/canonicalJson 1 MiB cap
    classifies as READ_INPUT_INVALID before the component limit checks
    (READ_COMPONENT_LIMIT_EXCEEDED); the extension-walk dedup is object
    identity in JS — strict JSON inputs carry no aliasing, so the port's
    per-path dedup is exact for every representable input (the one
    aliasing row was dropped from the fixture as unrepresentable).
  - **A2c part 2 (partially landed 2026-10-06):**
    `Semantics/R2Semantics.swift` ports `validateR2` — the whole-read path
    (the released function's `scope` variant belongs to the partial-read
    flows, Stage B): the full registry relinking with scopes
    (applies/covers/subset), contract/value checks, component bodies,
    method roles, judgments with units and bindings, ports and result
    compatibility, relationships, dependencies, examples (including the
    partial-outcome entry ordering), revisions, attributions and closures.
    Parity: the full post-validation registry state on all eight assets —
    ordered records, edges with insertion-ordered links, reference roles,
    unresolved externals and closures — is **byte-identical** (2.0 MB of
    canonical JSON) to the released `validateR2`. Two porting facts pinned
    again in this pass: JS Map insertion order is observable through link
    insertion (the `unique` helper now returns an insertion-ordered map)
    and the dependency's `producer_port` is a top-level field (not nested
    under `producer`). One declared gap: `r2-plan.js` (the finite authored
    plan graph, 312 lines) is the next package; until it lands a judgment
    carrying `method.plan` fails loudly with READ_CORE_CAPABILITY_UNAVAILABLE
    here instead of being silently unvalidated (no acceptance asset carries
    plans; the registry dump covers none). `canonical-ir` (buildIR) is the
    finale after that, with the derived-IR digest acceptance.
  - **A2c part 3 (landed 2026-10-06):** the plan gap is closed —
    `Semantics/R2Plan.swift` ports `checkPlans` point-by-point with the
    helpers carried as context methods (the released code keeps them in the
    per-judgment context closure; the formation-policy section uses them
    across judgments): node graph shape and reachability, ports and
    endpoints, input supplies, links with round checks, feedback state and
    update rules, result bindings and contributing closure, method
    contribution and the emission-list contract coupling. Verified with a
    synthetic plan matrix (a schema-legal plan grafted onto the synthetic
    trustworthy-data-comparison payload): the success case's full
    post-validation registry state and five negative variants (root
    mismatch, detached node, self link, missing input supply, binding to a
    missing port) with their field pointers are byte-identical to the
    released chain (111 KB canonical JSON). Two porting bugs pinned while
    fixing the matrix: `unique`-map lookups must go through the canonical
    key (the JS Map keys raw values), and a unit's `method` is the term
    string, not the method object. The 8-asset validateR2 registry-state
    parity (2.0 MB) was re-verified after wiring the real plan pass.
  - **A2 complete (2026-10-06):** `Semantics/CanonicalIR.swift` ports
    `buildIR` — role naming and stable identity ids, reference meanings,
    catalog, mandatory closures, the global asset closure, display index
    and the expansion-target passes — then validates CanonicalIR and
    checks interpretation completeness. **The finale acceptance passes:**
    for all eight local assets the FULL derived IR — 3.1 MB to 9.8 MB of
    canonical JSON per asset, ~57 MB in total — is **byte-identical** to
    the released `buildIR`, the derived and restored IR digests match, and
    the chain's own `SECTION_DERIVED_IR_MISMATCH` cross-check is `true`
    on both sides. One recorded equivalence: the released `visit` pair
    also walks the manifest for extension carriers; Manifest06Candidate
    has no extension positions, so the payload walks are equivalent (the
    note stands until a manifest grows one). The 0.5-generation semantic
    stack is now fully ported and parity-verified: contract, registry,
    values, components, static policies, r2 semantics, the plan graph and
    the canonical IR.
  - **A2 closeout — cross-entry (landed 2026-10-06):**
    `Semantics/CrossEntry.swift` ports all eight obligations
    (form consistency, asset capability, unique identity incl. the nested
    resolution targets, definition-term uniqueness, parent closure,
    core-term vocabulary, the navigation-label ban, lifecycle
    replacement rules) with rule ids, violation paths and messages
    verbatim; `assertPayload` surfaces the first violation as
    READ_CORE_INVALID with its field pointer and rule id
    (`PublicFailure.crossEntryRule`),
    `SectionDigests.validateDecodedPayload` composes the full
    semantic-admission path (Payload shape, asset bindings, cross-entry).
    Parity: `checkPayload`'s complete eight-rule reports on the eight
    assets plus eight per-rule mutation cases — and the `assertPayload`
    code/field/rule for each — are byte-identical to the released chain;
    committed `crossentry-micro-oracles.json` (21 synthetic micro-rows,
    one clean base plus per-rule mutations) with `CrossEntryTests`. One
    Swift pitfall pinned while porting: a ternary's `nil` branch with a
    contextually-typed optional infers `KDNAValue.null` (the type is
    ExpressibleByNilLiteral) instead of `Optional.none` — the absent case
    is written with an explicit branch instead. With this, everything the
    whole-read face calls is ported; A3 (the faces and envelopes) is next.
    Correction appended 2026-10-06, found by a full-suite flake while
    landing the fixture package: the parent-closure cycle report iterated
    a Swift Dictionary (`parentOf.keys`), whose per-process randomized
    order made the cycle's first node — and with it the reported message
    and path — nondeterministic across runs, while the released rule
    iterates a JS Map in judgment-declaration order. The key order is now
    carried explicitly; eight fresh-process filtered runs and three
    full-suite runs are deterministic, and the committed oracle row
    (which the flaking test asserted) was already Node's order.
  - **A3 whole-read faces (landed 2026-10-06):**
    `Sections/SectionFaces.swift` ports the
    `executeSectionNode` read path point-by-point — opaque request /
    authority / snapshot tokens, the admission envelope with the closed
    stage list and the classify() unsupported/rejected split, the
    in-memory-bytes capture (the design-sanctioned variant: same metadata
    scan, identity fields, one-shot latch and consistency checks; io is
    empty without file reads — recorded), the protection gate, the
    authorization context with the signature read intent, the strict
    `true` grant rule, the capture-changed check, the full semantic chain
    (restore → reconstruct → validateDecodedPayload → buildIR → derived-IR
    cross-check → observeWhole → bindings → checksums → signatures) and
    the WholeSectionSnapshotData06 assembly (digests evidence,
    verification block with capture table-frames). `SectionChecksums`
    ports the whole-read verification (absent / verified_document_2 with
    the first-difference pointer); `SectionSignatures` ports policy, the
    read intent and the unsigned path. **Acceptance:** on all eight local
    assets the complete snapshot data plus the envelope
    (`input_byte_length`; the `section-snapshot:` / `capture:` UUIDs
    normalized) is **byte-identical** to the released chain — 57 MB of
    canonical JSON — and the denied-callback case matches
    (`SECTION_PERMISSION_DENIED`, stage `authorization`, diagnostic
    `null`). Two declared gaps, both fail closed — correction (c0 review,
    2026-10-06): the partial modes are **not** served by "the released
    unsupported envelope"; the released chain implements
    catalog/exact_selection/expand, and the port's placeholder envelope is
    its own fail-closed stand-in (the placeholder codes are unreachable in
    the released mode enum). Catalog landed 2026-10-06 (see below);
    exact_selection/expand remain the Stage B parity target. A signed asset
    fails at the integrity stage until the kdsig ed25519 stack is ported.
    Pitfalls pinned: the
    envelope's `diagnostic` is the whole object or `null` (not a
    field/null pair), and comparator harnesses must embed the snapshot as
    a parsed object — a 9 MB canonical string trips the 1 MiB
    string cap in the strict canonicalizer on both sides.
  - **Fixture package (landed 2026-10-06):** the committed synthetic
    sections asset, produced and regenerable through the released creation
    path. Enabling discovery first: `reconstructPayload` → the released
    creation path (`createSectionAssetNode`) **round-trips byte-identically**
    on the two synthetic 0.5.1 bundles (craft-course-standards 0.1.0:
    762,476 bytes; trustworthy-data-comparison 1.1.0: 614,932 bytes,
    verified in scratch against released 0.36.0) — so the committed fixture
    bytes are reproducible by a reviewer from its own authored inputs.
    Committed under `Fixtures/`: `sections-fixture-craft-course-0.1.0.kdna`
    (762,476 bytes; sha256 `5f87e64f…078e`),
    `sections-fixture-craft-course-0.1.0.authorship.json` (the retained
    manifest + the creation payload + the regeneration record; 110,512
    bytes) and `regenerate-sections-fixture.mjs` (pinned to the released
    `@aikdna/kdna-core@0.36.0` via the `KDNA_CORE_RELEASE_ROOT` env
    variable — no absolute local paths; verified output: "regenerated bytes
    are identical to the committed fixture"). `SectionsFixtureTests` runs
    the whole-read face on the committed bytes and asserts the
    released-chain digest table: A `5f87e64f…078e`, C `82a172ca…c742`,
    E `36ce3a6e…c86e`, IR `aa3f961a…d747`, asset
    `asset:course-craft-standards` 0.1.0 / judgment 0.1.0, 8 judgments,
    190 IR nodes, runtime entries `kdna.json` + three packs. The fixture
    declares **no** `content_digest` and ships no `checksums.json` /
    `signature.kdsig`, so the snapshot's C and E comparison state is
    `not_compared` and checksum/signature integrity is `absent` — the
    observed-vs-declared separation is pinned as committed evidence, and
    the A2a-deferred synthetic-positive payload row is now served by this
    fixture (its payload passes `validate('Payload')` and cross-entry
    inside the accepted read). The four-bundle digest comparison table
    (A/C/E + IR per released chain) was computed in the same scratch
    environment and is carried by the review package for c0+f2 as §7
    specifies — these are local-only materials and their table does not
    enter this repo.
  - **Public asset-hung surface (landed 2026-10-06):**
    `Sections/SectionAsset.swift` exposes the confirmed surface (§4/§6
    binding: KDNA* prefix, asset-hung, phase tokens mandatory through the
    phases) as a thin public wrapper over the internal faces:
    `KDNASectionAsset.open(bytes:expectedSHA256:)` (container rules +
    manifest view + sections contract must hold; the optional expected
    digest is checked first), `admitSectionRequest(_:)` and the canonical
    `admitWholeReadRequest(requestId:budgetBytes:)`,
    `createReadAuthority` with the `Bool?` callback rule (only
    `.some(true)` grants; `.none` / `.some(false)` / thrown all deny —
    the Node strict `!== true`), and `readWhole` returning the closed
    envelope plus the opaque snapshot token. Internal failures cross the
    boundary as the closed `KDNASectionError.code`; the asset carries
    `fileSHA256`, the parsed `manifest` view and the contract `tuple`.
    Committed `SectionAssetAPITests` pins acceptance on the committed
    fixture through the public surface (accepted whole read incl. the IR
    digest; denied callback → SECTION_PERMISSION_DENIED without a
    snapshot; expected-digest mismatch → READ_INPUT_INVALID). Motivation:
    the coach app consumer uses exactly this surface
    (its loader migration lands with it). Full suite 39/39 green.
  - **Catalog face (landed 2026-10-06):**
    `Sections/SectionLayout.swift` ports `readSectionLayout` — the metadata
    bindings (descriptor node-ref digests included), the table
    directory/frame walk with every closed code, the topic/volume/xref
    coverage obligations, the mandated physical order and the pack span
    checks; the capture gained the full row records, the touched-member
    set and the member reads (checksum/signature members through the
    stored-or-inflate + CRC path; the fd stat-key re-checks have no bytes
    analogue). `SectionChecksums` gained the scoped prepare/complete pair
    (touched-partition semantics, the runtime-entry-set preimage, the
    closed first-difference pointers) and `SectionSignatures` the scoped
    `authorizationContext` / `readScoped` / `completeScoped` (unsigned
    intents read nothing extra; a signed asset still fails closed at the
    kdsig gap). `SectionFaces.readCatalog` assembles the metadata-only
    snapshot (`CatalogSectionSnapshotData06`: catalog, asset index and the
    scoped verification with A/C/E reported `not_checked`); the public
    asset gained `readCatalog` + `admitCatalogRequest`. **Parity: for all
    eight local assets the catalog snapshot plus envelope is
    byte-identical to the released chain** (50–59 KB of canonical JSON
    each, UUIDs normalized) — recon confirmed c0's finding that the
    released chain serves these modes. Committed:
    `SectionsFixtureTests.testCatalogReadFixture` (whole-output digest
    `3199074e…77c4`, recomputed from released 0.36.0 for the fixture and
    its request id) and `testUnportedPartialModesFailClosed` (f2 review
    item: the two remaining placeholder codes pinned as the port's own
    fail-closed behavior, not the released behavior). Full suite 41/41
    green.
  - **Structure layer (landed 2026-10-06, Stage B chunk 2a):**
    `Sections/StructureScanner.swift` ports the diagnostic structural
    scanner (`scanFrame`: a definite-CBOR walk with the retained-path
    policy, skipped text neither UTF-8/schema validated nor hashed, and
    the verbatim SCAN_* codes — including the released half-float
    arithmetic and the exact-integer round-trip rule); `Sections/
    Structure.swift` ports `inspectStructure` + `checkPartitionBindings`
    (per-frame observed-read digests, frame identity/record/owner checks,
    then the unchanged Core registry re-run on the structurally observed
    registration inputs with stable-node-id, owner, activation and
    typed-id comparisons; the C.keys failures map to
    READ_CORE_CAPABILITY_UNAVAILABLE exactly as the released boundary
    does). The capture gained `structureAfterAuthorization` (the
    consume-style frame reads with the touched-member rule). **Parity:
    for all eight local assets the full inspection
    `{observation, nodes, binding}` is byte-identical to the released
    chain** (150–223 KB of canonical JSON each, capture UUID
    normalized). Committed:
    `SectionsFixtureTests.testStructureInspectionFixture` (frame digests,
    read/skip accounting and the whole-output digest `ed47060b…21f8`;
    the catalog pin comment's byte count was dropped per the c0
    re-verification note). Next Stage B chunks: loaded validation + the
    fixed-point closure + scoped materialization, then the
    exact_selection face and the expansion binding.
  - **Scoped validation + interpretation inputs (landed 2026-10-06,
    Stage B chunk 2b-1):** `validateR2` gained the released `scope`
    parameter (`R2ValidationScope`: the structurally observed registry,
    the loaded-judgment set, the complete-judgment set for emission
    policies and the complete-policy-uses hook) with the four gated
    traversals (`activeRecord` on the contract/record/component loops,
    `activeJudgments` on the judgment pass) and the plan graph seeing the
    active subset — `scope == nil` keeps the whole-read path exactly as
    landed. `SectionLoadedValidation.readInterpretationInputs` ports the
    topic-frame interpretation read; the scanner gained the
    `interpretationInputs` retention option (the method/extensions/
    result_contract/formation_rule/parent_ref/lifecycle subtrees and
    every extension position are read and hashed; the rest of the body
    text stays unobserved). **Parity: the full `{judgments, frames}` is
    byte-identical to the released chain on all eight local assets**
    (31–53 KB of canonical JSON each). Committed
    `SectionsFixtureTests.testInterpretationInputsFixture` (frame digests,
    read/skip accounting and the whole-output digest `a2d8b6f2…afe0`).
    Remaining for the exact_selection face: the loaded schema/scalar
    passes (`validateAuthored` with the Ajv field pointers), the scoped
    cross-entry variant, the fixed-point closure and the scoped
    materialization.
  - **Loaded schema pass + scoped cross-entry (landed 2026-10-06, Stage B
    chunk 2b-2):** `SectionLoadedValidation.validateAuthored`
    (embedded-shape validation against the 0.5 contract — refs resolve
    into its types — with the Ajv-style field pointer, then the
    shape-level scalar pass) and `validateLoadedSchema` (required payload
    fields, per-field property shapes, loaded judgments against
    Judgment, the interpretation judgments' authored children, then the
    cross-entry obligations); `CrossEntry.assertScopedPayload` (the graph
    rules run over the interpretation headers, the body rules over the
    loaded subset with the local→full index remap; ASSET-CAPABILITY is
    skipped). The schema engine gained `PublicSchema.firstError` — the
    first-error analogue: unions report at the value's path,
    additionalProperties at the parent path, `required` with the missing
    name. **Acceptance: a nine-case probe matrix on two assets matches
    the released chain exactly** (reason + field pointer +
    crossEntryRule, including the gating proof that a broken unloaded
    judgment passes and the local→full pointer remap), committed as
    `SectionsFixtureTests.testLoadedValidationProbeMatrix`. Recorded
    named difference: multi-violation first-error ORDERING follows this
    port's fixed traversal (type/const/enum/bounds → unions →
    required/properties/additionalProperties → items → allOf); every
    single-violation probe matches Ajv.
  - **Fixed-point closure + scoped materialization (landed 2026-10-06,
    Stage B chunk 2b-3):** the registry record reads now carry the scoped
    missing-body trap — the released code re-defines a record's `value`
    property with a throwing getter, mirrored here as `checkedValue()` (a
    read of an inactive judgment's value raises `MissingBodyError`); the
    whole-read path's reads are unchanged. `SectionScopedMaterialize`
    ports `materializeScoped` (asset projection with the original Manifest
    values authoritative, the judgment catalog check, the reference set
    with declared/mandatory/optional meanings, the display-name index
    subset, the mandatory and global closures, the unresolved externals)
    and `SectionFixedpoint` ports `deriveMandatoryContext` (registration
    payload, the trap-armed scoped validation, the closure derivation with
    the available-edge expansion and the per-record expansion scopes, the
    declared-closure comparison, the interpretation observation and the
    iteration log). **Acceptance: the full derived context is
    byte-identical to the released chain on three selections of the
    committed fixture** — the full catalog (2,361,744 canonical bytes),
    one judgment (606,017) and two judgments (887,744) — including the
    missing-body iteration dynamics (the one-judgment run loads exactly
    self-verifiable-assessment → arc-sequencing → audience-fit →
    transfer-protocol); committed as
    `SectionsFixtureTests.testFixedpointParity`. Two porting bugs pinned
    while making it match: the scoped judgment loop must iterate the
    active subset, and the registry's null reference role is the
    empty-string key (a `??`-on-non-optional fallback bug).
  - **Exact-selection face (landed 2026-10-06, Stage B chunk 2b-4):**
    `SectionFaces.readExactSelection` ports the scoped flow end to end —
    the selection validated against the catalog and normalized to catalog
    order before authorization (`SECTION_SELECTION_ASSET` /
    `SECTION_SELECTION_MISSING`), the normalized admitted token, the
    scoped checksums, layout, structure observation and closure, the
    merged checked sections (closure rows without `why`), the runtime
    mandatory-entry check, the scoped checksum/signature completion, and
    the `SectionSnapshotData06` assembly with the structure observation
    and interpretation inputs in the verification block.
    `SectionExpansion.retain` stores the origin record on the snapshot
    object (the released WeakMap analogue; the in-memory variant's
    source identity is empty — recorded); the public asset gained
    `readExactSelection` + `admitExactSelectionRequest`, and the
    outcome carries the opaque normalized request token.
    **Acceptance: the accepted snapshot plus envelope is byte-identical
    to the released chain on three selections of the fixture** — full
    catalog (2,367,920 canonical bytes), a two-judgment prefix (893,374)
    and a reordered pair proving the catalog-order normalization
    (780,713); committed as `SectionsFixtureTests.testExactSelectionParity`.
  - **Expand binding + expand read (landed 2026-10-06, Stage B chunk
    2b-5):** the whole read now retains its origin (the missing
    `expansion.retain` the released flow performs) and `SectionExpansion`
    ports the origin value and `bind` — the caller's ExpansionHandle is
    validated against the retained view (snapshot identity, A/C digests,
    tuple, anchor, target and scope; whole-origin handles carry no
    `binding_kind`, scoped-origin handles require `binding_kind:
    section_capture` plus the origin record; the READ_HANDLE_* codes
    verbatim) — plus `checkCapture`. The scoped flow is shared by
    exact_selection / expand: an expand request needs the binding token
    (`READ_HANDLE_UNTRUSTED` otherwise), its selection is optional, and
    the closure runs with the bound target/scope (the asset index
    filters to the ordered scope with the scope-digest check;
    `expansion_targets` stays empty on the expand snapshot). Public
    surface: `readExpand` + `bindExpansionRequest`. **Acceptance:
    whole-origin and scoped-origin expansions are byte-identical to the
    released chain on the fixture** — with the run-bound snapshot UUID
    and the request digests that bind it normalized (every other byte
    exact) — and the four negative codes match
    (`READ_HANDLE_STALE` / `READ_HANDLE_SCOPE_MISMATCH` /
    `SECTION_TYPED_SHAPE` / `READ_HANDLE_UNTRUSTED`); committed as
    `SectionsFixtureTests.testExpandBindingParity`. Recorded: the
    in-memory capture's source identity is empty, so `checkCapture`'s
    identity comparison is vacuous there while every digest field is
    checked. Remaining Stage B: the retained read faces (retained-common /
    retained-plan / retained-state with the host gate), then the kdsig
    ed25519 stack.
- **Stage A3:** whole-read/catalog faces and the consumer loader acceptance.
  Sequencing note: the judgment-supply projection the Render adapter
  consumes comes from the A1 whole-frame path, so A3 can land against A1
  + digests while A2 completes the IR cross-check; the chain's own
  admission semantics include that cross-check, so A2 remains required
  for a faithful port and for hostile-vector fidelity.

## 6. API sketch (for open-line alignment — early, per the review flow)

```swift
public struct KDNASectionsTuple: Equatable { /* the ten fields, consts */ }

public final class KDNASectionAsset {
    public static func open(bytes: [UInt8], expectedSHA256: String? = nil) throws -> KDNASectionAsset
    public var manifest: KDNASectionManifest   // decoded kdna.json view
    public var fileSHA256: String
    public var tuple: KDNASectionsTuple
    // faces
    public func admitSectionRequest(_ request: KDNASectionReadRequest) throws -> KDNAAdmittedSectionRequest
    public func readWhole(_ admitted: KDNAAdmittedSectionRequest) throws -> KDNASectionSnapshot
    public func readCatalog(_ admitted: KDNAAdmittedSectionRequest) throws -> KDNASectionSnapshot
    public func readExactSelection(_ admitted: KDNAAdmittedSectionRequest) throws -> KDNASectionSnapshot
    public func sectionBytes(_ snapshot: KDNASectionSnapshot, sectionId: String) throws -> [UInt8]
    // Retained faces (asset-hung; Node semantics preserved: snapshot leading
    // among the arguments, three arguments total):
    public func prepareRetainedRead(
        _ snapshot: KDNASectionSnapshot,
        _ request: KDNAAdmittedSectionRequest,
        _ authority: KDNASectionReadAuthority
    ) throws -> KDNAPreparedRetainedRead        // one-shot token
    public func readRetained(
        _ prepared: KDNAPreparedRetainedRead,
        host: KDNATrustedHostReadProvider
    ) throws -> KDNARetainedReadResult
}

public final class KDNASectionReadAuthority {
    public static func create(
        callback: @escaping (KDNAValue) async throws -> Bool?,
        signaturePolicy: KDNASignaturePolicy
    ) throws -> KDNASectionReadAuthority   // non-function callback → RETAINED_AUTHORITY_CALLBACK (typed)
}

public struct KDNASectionReadRequest {   // closed union: whole|catalog|exactSelection|expand
    public static func whole(requestId: String, budgetBytes: Int) -> Self
    public static func catalog(requestId: String, budgetBytes: Int) -> Self
    public static func exactSelection(requestId: String, budgetBytes: Int, assetId: String, assetVersion: String, judgmentIds: [String]) -> Self
}

public enum KDNASectionDiagnostic: Error {   // closed codes, verbatim
    case rejected(code: String, stage: String, field: String?, subject: String?)
    case unsupported(reason: String, stage: String)
}
```

Surface naming/shape questions for the open line: (1) keep the existing
`KDNA*` type prefix; (2) whether faces hang off an asset object or free
functions mirroring the Node module split; (3) whether the retained
authority callback takes a Swift closure enforcing `.some(true)` like the
Node literal-`true` rule. These are the items sent for early alignment.

## 7. Conformance and fixtures

The Node repo has **no sections fixtures**; this port generates its own
golden set and checks in, per fixture: the exact bytes, the Node-chain
outputs (manifest view, A/C/E, IR digest, per-frame sha256, catalog), and
the expected diagnostics for hostile mutations.

**Privacy is a hard item (f2 requirement, re-emphasized by c0):** the
checked-in goldens are **synthetic assets** built to exercise the same
format paths (plus hostile-mutation vectors) — **zero real coach material
from the four bundles enters this public repo**; the four real bundles
serve only as LOCAL acceptance comparisons (digest equality, not
committed). Any real material in a fixture requires explicit Owner
clearing with a public-safe subset. Every fixture carries its
**regeneration method**: the **released version numbers** (e.g. core
0.36.0 / read 0.11.0) plus the generation script — scripts contain **no
absolute local paths**, so reviewers can replay them anywhere.
Hostile-mutation diagnostic expectations are recorded as **verbatim
closed-code strings**. A machine-readable manifest (fixture → bytes
sha256 → each digest) is optional and welcome. The review package for
c0+f2 carries the **four-bundle digest comparison table** (A/C/E + IR,
byte-level, computed from the released artifacts in a scratch
environment) as the acceptance evidence.

Fixture format governance (c0 ruling): the public repo's own
`ParityTests` tradition governs; private ledger conventions do not enter
the public repo.

Byte-comparison obligation (confirmed): A/C/E and `digestCanonical` at the
digest level, byte-exact against the Node chain **from the released
artifacts in a scratch environment** — not against work-tree builds, and
not on re-serialized UI structures. Parity tests follow the package's
existing `ParityTests.swift` tradition.

## 8. Hardest bits (flagged early)

1. ECMAScript `Number::toString` in JCS (shortest round-trip, `-0` → `0`,
   `1e21`/`1e-7` thresholds) — needed for C/E/IR digests.
2. The UTF-16 vs UTF-8 ordering split (two comparators, never unified).
3. Strict CBOR two-phase equality (key order is load-bearing).
4. Exact ZIP subset incl. the forward routing locator and one-shot
   latch semantics.
5. Closed-diagnostic fidelity (named differences only).

## 9. Process

Local-first on this branch; push gated by the Owner (repo under the
recovery-period seal; the open line has two unfreeze precedents to run
jointly). Review flow agreed with the open line: early API sketch (this
document's §6) → implementation → open-line review (c0 + f2) → Owner
release gate.

**Early alignment: PASSED** (f2 and c0, 2026-10-06). c0's answers were
implementation-verified against `sections-node.js` /
`retained-sections-node.js` (core 0.36.0): KDNA* prefix with a pre-landing
collision sweep; payload-discipline over receiver choice, with the retained
prepare kept three-argument and snapshot-leading; the authority callback
strictness spelled out above. c0 also logged the golden-fixtures proposal
(the first cross-implementation conformance vectors) as a borrowable asset
with no conflicts. f2 added four supplements, now folded into this
document: candidate-state mirroring (§ header, §2),
fixture privacy + per-fixture regeneration method (§7), digest-level
byte-comparison against the released artifacts in scratch (§7), and the
confirmed surface decisions (§4). The difficulty list (§8) was judged
accurate. Plaintext sections containers byte-compare across runs;
protected artifacts (salted) must not (same-run triple consistency only).
