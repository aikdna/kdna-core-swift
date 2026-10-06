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

A real consumer needs it: CoachLettersAI (gvjl) ships the re-authored
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

## 4. Swift architecture

New within `Sources/KDNACore` (additive; keep existing public surfaces):
`Sections/SectionZIP.swift` (strict ZIP subset over the existing
hand-rolled inflate), `Sections/StrictCBOR.swift` (the two-phase strict
walk over a minimal CBOR reader — no dependency; `0xb9`/`0xfb` shapes
pinned), `Sections/CanonicalJSON.swift` (JCS with **ECMAScript number
formatting** — the acknowledged hardest piece),
`Sections/SectionContainer.swift`, `Sections/FrameGraph.swift`,
`Sections/MetadataCodec.swift`, `Sections/SectionDigests.swift` (A/C/E +
IR), `Sections/SectionFaces.swift` (admission/snapshot/modes/bytes),
`Sections/RetainedRead.swift`, `Sections/Diagnostics.swift` (closed code
enums). Tokens become opaque final classes with a registry mirroring the
WeakMap discipline. TOCTOU: where file-based reads are used, re-check a
stat key before/after every read as the Node fd capture does; the initial
port may operate on in-memory bytes (the gvjl app loads bundle resources),
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
  adapter surfaces them). Acceptance: gvjl `KDNALoaderServiceTests` green
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
**regeneration method**: the released-artifact versions used and the
generation script, so reviewers can replay it. Hostile-mutation
diagnostic-expectation sets are explicitly welcome.

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
