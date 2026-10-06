import XCTest
import Foundation
@testable import KDNACore

// End-to-end whole-read acceptance on the committed synthetic fixture
// (regenerated through the released creation path; see the fixture's
// authorship JSON and regenerate-sections-fixture.mjs). Every digest below
// is the released chain's value for this exact byte sequence.
final class SectionsFixtureTests: XCTestCase {
    func testWholeReadFixtureDigestTable() async throws {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "sections-fixture-craft-course-0.1.0", withExtension: "kdna", subdirectory: "Fixtures"))
        let bytes = [UInt8](try Data(contentsOf: url))
        XCTAssertEqual(sha(Data(bytes)), "sha256:5f87e64fbc57637051d3bb692dc5e168e3e4328b8073d06bbfd9c1b0eb16078e")
        let tuple = try SectionContract.loadedContract.get()["module"]["versionTuple"]
        let admitted = try SectionFaces.admitSectionRequest(["request_id": "fixture-read-1", "tuple": tuple, "budget_bytes": .number(1048576),
                                                             "mode": "whole_asset", "selection": .null, "handle": .null])
        let authority = try SectionFaces.createSectionReadAuthority { _ in .bool(true) }
        let outcome = await SectionFaces.readWhole(bytes, admitted, authority)
        let envelopeText = String(decoding: (try? KDNAJSON.canonical(outcome.envelope)) ?? Data(), as: UTF8.self)
        XCTAssertEqual(outcome.envelope["status"].text, "accepted", envelopeText)
        XCTAssertEqual(outcome.envelope["input_byte_length"].numeric, 762476)
        let view = try XCTUnwrap(outcome.snapshot).inspect()
        XCTAssertEqual(view["digests"]["A"]["observed"].text, "sha256:5f87e64fbc57637051d3bb692dc5e168e3e4328b8073d06bbfd9c1b0eb16078e")
        XCTAssertEqual(view["digests"]["C"]["observed"].text, "sha256:82a172ca6154f218886c29f4dda2a4e32c714e059f3e5156c89f5416b210c742")
        XCTAssertEqual(view["digests"]["E"]["observed"].text, "sha256:36ce3a6edf273f924a0d4508b2385038ab4adc54f77218dcd4f1d0558db2c86e")
        XCTAssertEqual(view["digests"]["C"]["comparison"]["state"].text, "not_compared")
        XCTAssertEqual(view["digests"]["E"]["comparison"]["state"].text, "not_compared")
        XCTAssertEqual(view["digests"]["E"]["profile_version"].text, "0.3.0-candidate")
        XCTAssertEqual(view["asset"]["asset_id"].text, "asset:course-craft-standards")
        XCTAssertEqual(view["asset"]["asset_version"].text, "0.1.0")
        XCTAssertEqual(view["asset"]["judgment_version"].text, "0.1.0")
        XCTAssertEqual(view["ir"]["nodes"].list.count, 190)
        XCTAssertEqual(view["verification"]["semantic_status"].text, "verified_whole_graph")
        XCTAssertEqual(view["verification"]["routing_integrity"].text, "checked")
        XCTAssertEqual(view["verification"]["checksum_integrity"]["status"].text, "absent")
        XCTAssertEqual(view["verification"]["signature_integrity"]["status"].text, "absent")
        XCTAssertEqual(view["verification"]["whole_container_digest"]["digest"].text, view["digests"]["A"]["observed"].text)
        XCTAssertEqual(view["verification"]["whole_content_digest"]["digest"].text, view["digests"]["C"]["observed"].text)
        XCTAssertEqual(view["verification"]["ir_digest"]["digest"].text, "sha256:aa3f961aa78506f9d804b28c2abb52dd29d9a26a802ab825f3608474f6ced747")
        XCTAssertEqual(view["runtime_entry_names"].list.map { $0.text }, ["kdna.json", "sections/pack-0.kdnab", "sections/pack-1.kdnab", "sections/pack-2.kdnab"])
    }
    func testCatalogReadFixture() async throws {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "sections-fixture-craft-course-0.1.0", withExtension: "kdna", subdirectory: "Fixtures"))
        let bytes = [UInt8](try Data(contentsOf: url))
        let asset = try KDNASectionAsset.open(bytes: bytes)
        let admitted = try asset.admitCatalogRequest(requestId: "fixture-catalog-1", budgetBytes: 1048576)
        let authority = try asset.createReadAuthority { _ in true }
        let outcome = await asset.readCatalog(admitted, authority)
        XCTAssertEqual(outcome.envelope["status"].text, "accepted")
        XCTAssertEqual(outcome.envelope["input_byte_length"].numeric, 762476)
        let view = try XCTUnwrap(outcome.snapshot).inspect()
        XCTAssertEqual(view["catalog"].list.count, 8)
        XCTAssertEqual(view["asset_index"].list.count, 190)
        let verification = view["verification"]
        XCTAssertEqual(verification["mode"].text, "catalog")
        XCTAssertEqual(verification["semantic_status"].text, "metadata_only")
        XCTAssertEqual(verification["checked_sections"].list.map { $0["section_id"].text }, ["table:sections:0", "table:topics:0", "table:node_sections:0"])
        XCTAssertEqual(verification["unchecked_sections"].list.count, 18)
        XCTAssertEqual(verification["whole_container_digest"]["status"].text, "not_checked")
        XCTAssertEqual(verification["whole_content_digest"]["status"].text, "not_checked")
        XCTAssertEqual(verification["whole_content_digest"]["claimed_digest"], .null)
        XCTAssertEqual(verification["ir_digest"]["claimed_digest"].text.hasPrefix("sha256:aa3f961a"), true)
        XCTAssertEqual(verification["runtime_entry_digest"]["status"].text, "not_checked")
        XCTAssertEqual(verification["runtime_entry_digest"]["claimed_digest"], .null)
        XCTAssertEqual(verification["checksum_integrity"]["status"].text, "absent")
        XCTAssertEqual(verification["signature_integrity"]["status"].text, "absent")
        // Whole-output pin: the canonical catalog data with the two UUID
        // families normalized equals the released chain's digest for this
        // fixture and request id (recomputed from released 0.36.0).
        let text = String(decoding: try KDNAJSON.canonical(view), as: UTF8.self)
        let normalized = text
            .replacingOccurrences(of: "section-catalog:[0-9a-f-]{36}", with: "section-catalog:UUID", options: .regularExpression)
            .replacingOccurrences(of: "capture:[0-9a-f-]{36}", with: "capture:UUID", options: .regularExpression)
        XCTAssertEqual(sha(Data(normalized.utf8)), "sha256:3199074e931ffeb7b170c5f76ac666fce8ea007564971cf297fff93fb79877c4")
    }
    // Pins the entry-surface fail-closed behavior (review package §5): the
    // generic whole-read face declines partial modes with a contract-valid
    // unsupported envelope. The modes themselves are served by their
    // dedicated faces — see testCatalogReadFixture, testExactSelectionParity
    // and testExpandBindingParity; the released chain instead dispatches all
    // modes through one entry (recorded API-shape difference).
    func testUnportedPartialModesFailClosed() async throws {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "sections-fixture-craft-course-0.1.0", withExtension: "kdna", subdirectory: "Fixtures"))
        let bytes = [UInt8](try Data(contentsOf: url))
        let asset = try KDNASectionAsset.open(bytes: bytes)
        let authority = try asset.createReadAuthority { _ in true }
        let selection: J = ["asset_id": "asset:course-craft-standards", "asset_version": "0.1.0", "judgment_ids": ["fixture:judgment"]]
        let handle: J = ["handle_id": "fixture-handle-1", "asset_id": "asset:course-craft-standards", "asset_version": "0.1.0",
                         "A": .string("sha256:" + String(repeating: "a", count: 64)), "C": .string("sha256:" + String(repeating: "b", count: 64)),
                         "snapshot_id": "section-snapshot:fixture", "core_version": "0.36.0", "ir_version": "0.1.0", "read_version": "0.11.0",
                         "anchor": ["kind": "asset"], "target": ["kind": "asset", "id": "asset:course-craft-standards"],
                         "scope": .array([.string("fixture-scope")]), "issued_at": .number(0), "expires_at": .number(1),
                         "host_id": "host:fixture", "host_epoch": "epoch:1"]
        let requests: [(String, String, J, J)] = [("exact_selection", "PARTIAL_SEMANTIC_PROOF_UNAVAILABLE", selection, .null),
                                                  ("expand", "EXPAND_INTEGRATION_UNIMPLEMENTED", .null, handle)]
        for (mode, code, selectionValue, handleValue) in requests {
            let admitted = try asset.admitSectionRequest(["request_id": .string("fixture-\(mode)"), "tuple": asset.tuple,
                                                          "budget_bytes": .number(1048576), "mode": .string(mode), "selection": selectionValue, "handle": handleValue])
            let outcome = await asset.readWhole(admitted, authority)
            XCTAssertEqual(outcome.envelope["status"].text, "unsupported", mode)
            XCTAssertEqual(outcome.envelope["reason"].text, code, mode)
            XCTAssertNil(outcome.snapshot)
        }
    }
    func testStructureInspectionFixture() throws {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "sections-fixture-craft-course-0.1.0", withExtension: "kdna", subdirectory: "Fixtures"))
        let bytes = [UInt8](try Data(contentsOf: url))
        var capture = try SectionFaces.captureWhole(bytes)
        let manifest = try SectionManifest.load(capture.manifestBytes)
        let layout = try SectionLayout.readSectionLayout(&capture, manifest)
        let result = try SectionStructure.inspectStructure(&capture, layout, manifest)
        // Released-chain pins (recomputed from 0.36.0 on this fixture).
        XCTAssertEqual(result.observation["frames"].list.count, 9)
        let frame0 = result.observation["frames"].list[0]
        XCTAssertEqual(frame0["section_id"].text, "topic:craft:judgment-shift")
        XCTAssertEqual(frame0["observed_read_bytes"].numeric, 6438)
        XCTAssertEqual(frame0["read_calls"].numeric, 1516)
        XCTAssertEqual(frame0["skipped_text_bytes"].numeric, 8320)
        XCTAssertEqual(frame0["observed_ranges_digest"].text, "sha256:d76f755a9150ab6284585d6b771bac3d7b72a942e1268f679ad27dc2375d6e1b")
        XCTAssertEqual(result.binding["nodes"].numeric, 190)
        XCTAssertEqual(result.binding["judgments"].numeric, 8)
        XCTAssertEqual(result.binding["root_records"].numeric, 129)
        XCTAssertEqual(result.binding["full_semantic_validation"].boolean, false)
        let totalRead = result.observation["frames"].list.reduce(0) { $0 + Int($1["observed_read_bytes"].numeric) }
        let totalSkipped = result.observation["frames"].list.reduce(0) { $0 + Int($1["skipped_text_bytes"].numeric) }
        XCTAssertEqual(totalRead, 94476)
        XCTAssertEqual(totalSkipped, 85072)
        // Whole-output pin: canonical {observation, nodes, binding} with the
        // capture UUID normalized equals the released chain's digest.
        let out: J = ["observation": result.observation, "nodes": .array(result.nodes), "binding": result.binding]
        let text = String(decoding: try KDNAJSON.canonical(out), as: UTF8.self)
        let normalized = text.replacingOccurrences(of: "capture:[0-9a-f-]{36}", with: "capture:UUID", options: .regularExpression)
        XCTAssertEqual(sha(Data(normalized.utf8)), "sha256:ed47060b53a6a4a3aed802f4faba018a4b8fbf79436db9ef724f5fc0a1ac21f8")
    }
    func testInterpretationInputsFixture() throws {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "sections-fixture-craft-course-0.1.0", withExtension: "kdna", subdirectory: "Fixtures"))
        let bytes = [UInt8](try Data(contentsOf: url))
        var capture = try SectionFaces.captureWhole(bytes)
        let manifest = try SectionManifest.load(capture.manifestBytes)
        let layout = try SectionLayout.readSectionLayout(&capture, manifest)
        let structure = try SectionStructure.inspectStructure(&capture, layout, manifest)
        let inputs = try SectionLoadedValidation.readInterpretationInputs(&capture, layout, structure)
        // Released-chain pins (recomputed from 0.36.0 on this fixture).
        XCTAssertEqual(inputs["judgments"].list.count, 8)
        XCTAssertEqual(inputs["frames"].list.count, 8)
        let frame0 = inputs["frames"].list[0]
        XCTAssertEqual(frame0["section_id"].text, "topic:craft:judgment-shift")
        XCTAssertEqual(frame0["observed_read_bytes"].numeric, 7866)
        XCTAssertEqual(frame0["read_calls"].numeric, 1547)
        XCTAssertEqual(frame0["skipped_text_bytes"].numeric, 6892)
        XCTAssertEqual(frame0["observed_ranges_digest"].text, "sha256:7b800d5df5e0fa42b2e5b8b0ec9a679260511fee26eee1f7b18e47c4dd4bbc7c")
        let totalRead = inputs["frames"].list.reduce(0) { $0 + Int($1["observed_read_bytes"].numeric) }
        let totalSkipped = inputs["frames"].list.reduce(0) { $0 + Int($1["skipped_text_bytes"].numeric) }
        XCTAssertEqual(totalRead, 58747)
        XCTAssertEqual(totalSkipped, 47423)
        // Whole-output pin: the canonical {judgments, frames} equals the
        // released chain's digest (no UUIDs on this path).
        let text = String(decoding: try KDNAJSON.canonical(inputs), as: UTF8.self)
        XCTAssertEqual(sha(Data(text.utf8)), "sha256:a2d8b6f2d67a8a9b1108334f4319bdbf9dd0de92b1b06c1c13251c322463afe0")
    }
    // The loaded-schema probe matrix (frozen from the released-chain run;
    // every cell matched byte-for-byte in the scratch comparison): the
    // rejection reason, the Ajv-style field pointer and the scoped gating
    // (an unloaded broken judgment must pass).
    func testLoadedValidationProbeMatrix() throws {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "sections-fixture-craft-course-0.1.0", withExtension: "kdna", subdirectory: "Fixtures"))
        let bytes = [UInt8](try Data(contentsOf: url))
        var capture = try SectionFaces.captureWhole(bytes)
        let manifest = try SectionManifest.load(capture.manifestBytes)
        let entries = try SectionContainer.parse(Data(bytes))
        let restored = try SectionFrameGraph.restoreWholeFrames(entries, manifest)
        let payload = try SectionDigests.reconstructPayload(restored.ir)
        let layout = try SectionLayout.readSectionLayout(&capture, manifest)
        let structure = try SectionStructure.inspectStructure(&capture, layout, manifest)
        let interpretation = try SectionLoadedValidation.readInterpretationInputs(&capture, layout, structure)
        let allIds = payload["judgments"].list.map { $0["id"].text }
        func outcome(_ p: J, _ loaded: Set<String>, _ interp: J) -> String {
            do { try SectionLoadedValidation.validateLoadedSchema(p, loaded, interp); return "pass" }
            catch let failure as PublicFailure { return "\(failure.code)|\(failure.field ?? "-")|\(failure.crossEntryRule ?? "-")" }
            catch { return "other" }
        }
        XCTAssertEqual(outcome(payload, Set(allIds), interpretation), "pass")
        XCTAssertEqual(outcome(payload, Set([allIds[0]]), interpretation), "pass")
        var p = payload; p.remove("kernel")
        XCTAssertEqual(outcome(p, Set(allIds), interpretation), "SECTION_PAYLOAD_REQUIRED|-|-")
        p = payload; p["zzz_unknown"] = .string("x")
        XCTAssertEqual(outcome(p, Set(allIds), interpretation), "SECTION_PAYLOAD_FIELD|-|-")
        p = payload; p["scope"] = .number(123)
        XCTAssertEqual(outcome(p, Set(allIds), interpretation), "READ_CORE_INVALID|/payload/scope|-")
        var mutated = payload
        var judgment = mutated["judgments"].list[0]; judgment["focus"] = .number(123)
        var list = mutated["judgments"].list; list[0] = judgment; mutated["judgments"] = .array(list)
        XCTAssertEqual(outcome(mutated, Set(allIds), interpretation), "READ_CORE_INVALID|/payload/judgments/0/focus|-")
        XCTAssertEqual(outcome(mutated, Set([allIds[1]]), interpretation), "pass")
        var interp2 = interpretation
        var ij = interp2["judgments"].list[1]
        var method = ij["method"]; method["term"] = .number(123); ij["method"] = method
        var iList = interp2["judgments"].list; iList[1] = ij; interp2["judgments"] = .array(iList)
        XCTAssertEqual(outcome(payload, Set(allIds), interp2), "READ_CORE_INVALID|/payload/judgments/1/method|-")
        var cap = payload; cap["asset_capability"] = .string("asserted_answers")
        XCTAssertEqual(outcome(cap, Set([allIds[0]]), interpretation), "pass")
    }
    // The mandatory-context fixed point, pinned against the released chain
    // on three selections of the fixture: the full catalog, one judgment and
    // two judgments. The subset runs exercise the missing-body trap (the
    // body sequence must match the released chain's iteration log).
    func testFixedpointParity() throws {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "sections-fixture-craft-course-0.1.0", withExtension: "kdna", subdirectory: "Fixtures"))
        let bytes = [UInt8](try Data(contentsOf: url))
        let cases: [(String, Int?, Int, Int, Int, [String], String)] = [
            ("full", nil, 1, 187, 9, [], "sha256:7dd9fd0e58beec8eb292e573c55c215f0f610253079c66d41de73f233a46d207"),
            ("one", 1, 5, 91, 6, ["craft:self-verifiable-assessment", "craft:arc-sequencing", "craft:audience-fit", "craft:transfer-protocol"], "sha256:77af15a5ac3e148091d6fa381b4ffbe46bb8c33df08343f690f7e7e24264ef78"),
            ("two", 2, 5, 111, 7, ["craft:arc-sequencing", "craft:audience-fit", "craft:transfer-protocol"], "sha256:e16485d3cfb4cc341929391afa43265db7ae65368daf79f04b3cd0479ddc8a06"),
        ]
        for (label, count, iterationCount, selectedCount, checkedCount, bodySequence, digest) in cases {
            var capture = try SectionFaces.captureWhole(bytes)
            let manifest = try SectionManifest.load(capture.manifestBytes)
            let layout = try SectionLayout.readSectionLayout(&capture, manifest)
            let structure = try SectionStructure.inspectStructure(&capture, layout, manifest)
            let all = layout.meta["catalog"].list.map { $0["judgment_id"].text }
            let selected = count == nil ? all : Array(all.prefix(count!))
            let result = try SectionFixedpoint.deriveMandatoryContext(&capture, layout, manifest, structure, selected)
            XCTAssertEqual(result["iterations"].list.count, iterationCount, label)
            let bodies = result["iterations"].list.compactMap { $0["required_body"] != .null ? $0["required_body"].text : nil }
            XCTAssertEqual(bodies, bodySequence, label)
            XCTAssertEqual(result["selected_node_ids"].list.count, selectedCount, label)
            XCTAssertEqual(result["checked_sections"].list.count, checkedCount, label)
            let text = String(decoding: try KDNAJSON.canonical(result), as: UTF8.self)
            let normalized = text.replacingOccurrences(of: "capture:[0-9a-f-]{36}", with: "capture:UUID", options: .regularExpression)
            XCTAssertEqual(sha(Data(normalized.utf8)), digest, label)
        }
    }
    // The exact_selection face, pinned against the released chain on three
    // selections of the fixture (full, prefix-of-two, and a reordered pair
    // that proves the catalog-order normalization).
    func testExactSelectionParity() async throws {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "sections-fixture-craft-course-0.1.0", withExtension: "kdna", subdirectory: "Fixtures"))
        let bytes = [UInt8](try Data(contentsOf: url))
        let catalog = ["craft:judgment-shift", "craft:self-verifiable-assessment", "craft:transfer-protocol", "craft:arc-sequencing", "craft:lesson-rhythm", "craft:anti-patterns", "craft:evidence-and-sources", "craft:audience-fit"]
        let cases: [(String, [String], [String], Int, String)] = [
            ("all", catalog, catalog, 187, "sha256:1fd7901e72efff149183e70cfd1a2a07328b4eb03c11f63f40d596bf99d5b87c"),
            ("two", Array(catalog.prefix(2)), Array(catalog.prefix(2)), 111, "sha256:88bfb181ccaee8c3bcbed0149ab51593599b397c10e0ac021f8b95c746d6d9f9"),
            ("reordered", [catalog[5], catalog[0]], [catalog[0], catalog[5]], 103, "sha256:be45be6c4b4626c2de5582e4c2a356f5c99094255a605444bb6cd9099ffb2134"),
        ]
        for (label, requested, normalized, selectedCount, digest) in cases {
            let asset = try KDNASectionAsset.open(bytes: bytes)
            let admitted = try asset.admitExactSelectionRequest(requestId: "exact-" + label, budgetBytes: 1048576, assetId: "asset:course-craft-standards", assetVersion: "0.1.0", judgmentIds: requested)
            let authority = try asset.createReadAuthority { _ in true }
            let outcome = await asset.readExactSelection(admitted, authority)
            XCTAssertEqual(outcome.envelope["status"].text, "accepted", label)
            XCTAssertEqual(outcome.envelope["input_byte_length"].numeric, 762476, label)
            XCTAssertNotNil(outcome.normalizedRequest, label)
            let view = try XCTUnwrap(outcome.snapshot).inspect()
            XCTAssertEqual(view["verification"]["mode"].text, "exact_selection", label)
            XCTAssertEqual(view["verification"]["semantic_status"].text, "verified_loaded_closure", label)
            XCTAssertEqual(view["mandatory_closures"].list.map { $0["selection"]["judgment_id"].text }, normalized, label)
            XCTAssertEqual(view["selected_node_ids"].list.count, selectedCount, label)
            let out: J = ["status": outcome.envelope["status"], "input_byte_length": outcome.envelope["input_byte_length"], "data": view]
            let text = String(decoding: try KDNAJSON.canonical(out), as: UTF8.self)
            let normalizedText = text
                .replacingOccurrences(of: "section-scoped:[0-9a-f-]{36}", with: "section-scoped:UUID", options: .regularExpression)
                .replacingOccurrences(of: "capture:[0-9a-f-]{36}", with: "capture:UUID", options: .regularExpression)
            XCTAssertEqual(sha(Data(normalizedText.utf8)), digest, label)
        }
    }
    // The expand binding + expand read, pinned against the released chain:
    // a whole-origin expansion (empty selection closure) and a scoped-origin
    // expansion (the exact_selection origin), plus the four READ_HANDLE_*
    // negative codes. The run-bound digest normalization covers the random
    // snapshot UUID that the request digest binds (each run hashes its own
    // UUID; every other byte is compared exactly).
    func testExpandBindingParity() async throws {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "sections-fixture-craft-course-0.1.0", withExtension: "kdna", subdirectory: "Fixtures"))
        let bytes = [UInt8](try Data(contentsOf: url))
        func normalize(_ text: String) -> String {
            var out = text
            for family in ["section-snapshot", "section-scoped", "capture"] {
                out = out.replacingOccurrences(of: "\(family):[0-9a-f-]{36}", with: "\(family):UUID", options: .regularExpression)
            }
            return out.replacingOccurrences(of: "\"request_digest\":\"sha256:[0-9a-f]{64}\"", with: "\"request_digest\":\"sha256:RUN-BOUND\"", options: .regularExpression)
        }
        func outcomeText(_ outcome: SectionFaces.ReadOutcome) throws -> String {
            let view = try XCTUnwrap(outcome.snapshot).inspect()
            let out: J = ["status": outcome.envelope["status"], "input_byte_length": outcome.envelope["input_byte_length"], "data": view]
            return String(decoding: try KDNAJSON.canonical(out), as: UTF8.self)
        }
        // 1) whole-origin expand
        let asset = try KDNASectionAsset.open(bytes: bytes)
        let authority = try asset.createReadAuthority { _ in true }
        let whole = await asset.readWhole(try asset.admitWholeReadRequest(requestId: "whole-1", budgetBytes: 1048576), authority)
        let wholeView = try XCTUnwrap(whole.snapshot).inspect()
        let target = wholeView["ir"]["expansion_targets"].list[0]
        let handle: J = ["handle_id": "h1", "asset_id": wholeView["asset"]["asset_id"], "asset_version": wholeView["asset"]["asset_version"],
                         "A": wholeView["digests"]["A"]["observed"], "C": wholeView["digests"]["C"]["observed"], "snapshot_id": wholeView["snapshot_id"],
                         "core_version": wholeView["tuple"]["core"], "ir_version": wholeView["tuple"]["ir"], "read_version": wholeView["tuple"]["read"],
                         "anchor": ["kind": "asset"], "target": target["target"], "scope": target["scope"],
                         "issued_at": .number(0), "expires_at": .number(1), "host_id": "host:harness", "host_epoch": "epoch:1"]
        let candidate: J = ["request_id": "expand-whole", "tuple": asset.tuple, "budget_bytes": .number(1048576), "mode": "expand", "selection": .null, "handle": handle]
        let token = try KDNASectionAsset.bindExpansionRequest(whole.snapshot!, candidate)
        let expanded = await asset.readExpand(token, authority)
        XCTAssertEqual(expanded.envelope["status"].text, "accepted")
        let expandedText = normalize(try outcomeText(expanded))
        XCTAssertEqual(sha(Data(expandedText.utf8)), "sha256:a0096ed8ca7125f88d3c6add8fe460e38708afff200277f232f13ab8e9a73d6c")
        XCTAssertEqual(expanded.snapshot!.inspect()["verification"]["origin"] != .null, true)
        // 2) scoped-origin expand
        let exact = await asset.readExactSelection(try asset.admitExactSelectionRequest(requestId: "exact-1", budgetBytes: 1048576, assetId: "asset:course-craft-standards", assetVersion: "0.1.0", judgmentIds: ["craft:judgment-shift"]), authority)
        let exactView = try XCTUnwrap(exact.snapshot).inspect()
        let starget = exactView["expansion_targets"].list[0]
        let origin: J = ["snapshot_id": exactView["snapshot_id"], "request_digest": exactView["request_digest"],
                         "capture_id": exactView["verification"]["capture"]["capture_id"], "input_byte_length": exactView["verification"]["capture"]["input_byte_length"],
                         "manifest_bytes_digest": exactView["verification"]["capture"]["manifest_bytes_digest"],
                         "zip_directory_bytes_digest": exactView["verification"]["capture"]["zip_directory_bytes_digest"],
                         "checked_sections_digest": .string(sha(try KDNAJSON.canonical(exactView["verification"]["checked_sections"])))]
        let shandle: J = ["handle_id": "h2", "binding_kind": "section_capture", "asset": exactView["asset"], "tuple": exactView["tuple"], "origin": origin,
                          "anchor": starget["anchor"], "target": starget["target"], "scope": starget["scope"],
                          "issued_at": .number(0), "expires_at": .number(1), "host_id": "host:harness", "host_epoch": "epoch:1"]
        let scandidate: J = ["request_id": "expand-scoped", "tuple": asset.tuple, "budget_bytes": .number(1048576), "mode": "expand",
                             "selection": ["asset_id": "asset:course-craft-standards", "asset_version": "0.1.0", "judgment_ids": .array([.string("craft:judgment-shift")])], "handle": shandle]
        let stoken = try KDNASectionAsset.bindExpansionRequest(exact.snapshot!, scandidate)
        let sexpanded = await asset.readExpand(stoken, authority)
        XCTAssertEqual(sexpanded.envelope["status"].text, "accepted")
        let sexpandedText = normalize(try outcomeText(sexpanded))
        XCTAssertEqual(sha(Data(sexpandedText.utf8)), "sha256:28bb36e9b17c72619315ee1e55775a4c7ca0147d49164464a96b7bc2bd3da924")
        // 3) negatives
        func negative(_ mutate: (inout J) -> Void) -> String {
            var c = candidate
            mutate(&c)
            do { _ = try KDNASectionAsset.bindExpansionRequest(whole.snapshot!, c); return "pass" }
            catch let failure as KDNASectionError { return failure.code }
            catch { return "other" }
        }
        XCTAssertEqual(negative { $0["handle"]["A"] = .string("sha256:" + String(repeating: "0", count: 64)) }, "READ_HANDLE_STALE")
        XCTAssertEqual(negative { $0["handle"]["scope"] = .array(Array($0["handle"]["scope"].list.prefix(1))) }, "READ_HANDLE_SCOPE_MISMATCH")
        XCTAssertEqual(negative { $0["tuple"]["core"] = .string("0.0.0") }, "SECTION_TYPED_SHAPE")
        XCTAssertEqual(negative { $0["mode"] = .string("catalog"); $0["selection"] = .null; $0["handle"] = .null }, "READ_HANDLE_UNTRUSTED")
    }
    // The retained-preparation stack, pinned against the released chain on
    // ten cases (whole / exact / catalog / expand / expand-stale preparations
    // and five rejection details). The normalized digest covers the run-bound
    // UUIDs and the digests that bind them; every other byte is exact.
    func testRetainedPreparationParity() async throws {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "sections-fixture-craft-course-0.1.0", withExtension: "kdna", subdirectory: "Fixtures"))
        let bytes = [UInt8](try Data(contentsOf: url))
        let asset = try KDNASectionAsset.open(bytes: bytes)
        let readAuthority = try asset.createReadAuthority { _ in true }
        let whole = await asset.readWhole(try asset.admitWholeReadRequest(requestId: "w", budgetBytes: 1048576), readAuthority)
        let wholeView = try XCTUnwrap(whole.snapshot).inspect()
        let catalog = await asset.readCatalog(try asset.admitCatalogRequest(requestId: "c", budgetBytes: 1048576), readAuthority)
        var out: J = [:]
        func run(_ label: String, _ snapshot: KDNASectionSnapshot, _ candidate: J, deny: Bool = false, policy: J? = nil) async throws {
            let admitted = SectionRetained.admit(candidate)
            guard case .admitted(let request) = admitted else {
                if case .rejected(let value) = admitted { out[label] = ["admission": value] }
                return
            }
            var captured: J = .null
            let authority = try SectionRetained.createAuthority({ ctx in captured = ctx; return !deny }, policy)
            switch await SectionRetained.prepare(snapshot, request, authority) {
            case .rejected(let value): out[label] = ["prep": value]
            case .prepared(let prepared): out[label] = ["context": captured, "data": SectionRetained.inspectPreparation(prepared) ?? .null]
            }
        }
        func wh(_ mode: String, _ extra: J = [:]) -> J {
            var r: J = ["request_id": .string("r-" + mode), "tuple": asset.tuple, "budget_bytes": .number(1048576),
                        "mode": .string(mode), "selection": .null, "handle": .null]
            for (k, v) in extra.fields { r[k.text] = v }
            return r
        }
        try await run("whole", whole.snapshot!, wh("whole_asset"))
        try await run("exact", whole.snapshot!, wh("exact_selection", ["selection": ["asset_id": "asset:course-craft-standards", "asset_version": "0.1.0", "judgment_ids": .array([.string("craft:judgment-shift")])]]))
        try await run("catalog-origin", catalog.snapshot!, wh("catalog"))
        let originRecord: J = ["snapshot_id": wholeView["snapshot_id"], "kind": "whole",
                               "capture_id": wholeView["verification"]["capture"]["capture_id"],
                               "admission_request_digest": wholeView["verification"]["request_digest"],
                               "verification_digest": .string(sha(try KDNAJSON.canonical(wholeView["verification"]))),
                               "checked_sections_digest": .string(sha(try KDNAJSON.canonical(wholeView["verification"]["checked_sections"])))]
        let target = wholeView["ir"]["expansion_targets"].list[0]
        let handle: J = ["handle_id": "h", "asset": wholeView["asset"], "tuple": wholeView["tuple"], "origin": originRecord,
                         "anchor": ["kind": "asset"], "target": target["target"], "scope": target["scope"]]
        try await run("expand", whole.snapshot!, wh("expand", ["handle": handle]))
        var stale = handle
        stale["origin"]["snapshot_id"] = .string("section-snapshot:00000000-0000-0000-0000-000000000000")
        try await run("expand-stale", whole.snapshot!, wh("expand", ["handle": stale]))
        try await run("catalog-origin-with-whole-mode", catalog.snapshot!, wh("whole_asset"))
        try await run("denied", whole.snapshot!, wh("whole_asset"), deny: true)
        try await run("require-signature", whole.snapshot!, wh("whole_asset"), policy: ["requireSignature": true, "expectedPublicKeyHex": .null])
        var mixed = asset.tuple; mixed["read"] = .string("0.0.0")
        if case .rejected(let value) = SectionRetained.admit(["request_id": "x", "tuple": mixed, "budget_bytes": .number(1), "mode": "whole_asset", "selection": .null, "handle": .null]) {
            out["mixed-tuple"] = ["admission": value]
        }
        if case .rejected(let value) = SectionRetained.admit(["request_id": "x", "tuple": .number(3)]) {
            out["bad-shape"] = ["admission": value]
        }
        // rejection details
        func detail(_ label: String) -> (String, String) {
            let obj = out[label]["prep"] != .null ? out[label]["prep"] : out[label]["admission"]
            return (obj["status"].text, obj["detail"].text)
        }
        for (label, expected) in [("catalog-origin-with-whole-mode", "origin_scope_insufficient"), ("denied", "authority_denied"),
                                  ("require-signature", "signature_policy_unsatisfied"), ("mixed-tuple", "mixed_tuple"), ("bad-shape", "input_invalid")] {
            XCTAssertEqual(detail(label).1, expected, label)
        }
        for label in ["whole", "exact", "catalog-origin"] {
            XCTAssertEqual(out[label]["data"] != .null, true, label)
        }
        // Whole-output pin (run-bound UUIDs and the digests binding them normalized).
        var text = String(decoding: try KDNAJSON.canonical(out), as: UTF8.self)
        for family in ["section-snapshot", "section-scoped", "section-catalog", "capture"] {
            text = text.replacingOccurrences(of: "\(family):[0-9a-f-]{36}", with: "\(family):UUID", options: .regularExpression)
        }
        text = text.replacingOccurrences(of: "\"operation_id\":\"retained:[0-9a-f-]{36}\"", with: "\"operation_id\":\"retained:UUID\"", options: .regularExpression)
        for field in ["verification_digest", "intent_digest", "origin_receipt_digest"] {
            text = text.replacingOccurrences(of: "\"\(field)\":\"sha256:[0-9a-f]{64}\"", with: "\"\(field)\":\"sha256:RUN-BOUND\"", options: .regularExpression)
        }
        XCTAssertEqual(sha(Data(text.utf8)), "sha256:265fddf7e84c8053fcfbdc381712aa5c60024d94e924003d0cd699772ff9d683")
    }
    // The kdsig verification stack, pinned against the released chain on the
    // committed signed fixture (self-key and pinned-key verifications, the
    // wrong-pin / require-signature / tampered-signature rejections). The
    // fixture is regenerated with the unsigned one by the same script (the
    // deterministic test seed is documented there).
    func testSignedFixtureParity() async throws {
        let signedURL = try XCTUnwrap(Bundle.module.url(forResource: "sections-fixture-craft-course-0.1.0.signed", withExtension: "kdna", subdirectory: "Fixtures"))
        let unsignedURL = try XCTUnwrap(Bundle.module.url(forResource: "sections-fixture-craft-course-0.1.0", withExtension: "kdna", subdirectory: "Fixtures"))
        let signed = [UInt8](try Data(contentsOf: signedURL))
        let unsigned = [UInt8](try Data(contentsOf: unsignedURL))
        XCTAssertEqual(sha(Data(signed)), "sha256:21bf43204f42bbd1d6ce047e30796ed75f69cc507b8fa26910caaf605424aacc")
        let correctKey = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"
        var out: J = [:]
        func read(_ label: String, _ bytes: [UInt8], _ policy: J?) async throws {
            let asset = try KDNASectionAsset.open(bytes: bytes)
            let authority = try asset.createReadAuthority({ _ in true }, signaturePolicy: policy)
            let outcome = await asset.readWhole(try asset.admitWholeReadRequest(requestId: "signed-1", budgetBytes: 1048576), authority)
            if let snapshot = outcome.snapshot {
                out[label] = ["status": outcome.envelope["status"], "signature_integrity": snapshot.inspect()["verification"]["signature_integrity"]]
            } else {
                out[label] = ["status": outcome.envelope["status"], "reason": outcome.envelope["reason"],
                              "stage": outcome.envelope["stage"], "diagnostic": outcome.envelope["diagnostic"]]
            }
        }
        try await read("selfKey", signed, nil)
        try await read("pinned", signed, ["requireSignature": true, "expectedPublicKeyHex": .string(correctKey)])
        try await read("wrongPin", signed, ["requireSignature": true, "expectedPublicKeyHex": .string(String(repeating: "0", count: 64))])
        try await read("unsignedRequire", unsigned, ["requireSignature": true, "expectedPublicKeyHex": .null])
        // The tampered-signature case is covered by the scratch parity run
        // (the committed test pins the four cases above; rebuilding a
        // tampered container in-repo needs a stored-container writer, which
        // the open port does not expose).
        // rejection codes
        XCTAssertEqual(out["wrongPin"]["reason"].text, "SECTION_SIGNATURE_PIN_MISMATCH")
        XCTAssertEqual(out["wrongPin"]["diagnostic"]["field"].text, "/signature.kdsig/public_key")
        XCTAssertEqual(out["unsignedRequire"]["reason"].text, "SECTION_SIGNATURE_REQUIRED")
        XCTAssertEqual(out["selfKey"]["signature_integrity"]["status"].text, "verified_self_key")
        XCTAssertEqual(out["pinned"]["signature_integrity"]["status"].text, "verified_pinned_key")
        XCTAssertEqual(out["selfKey"]["signature_integrity"]["public_key"].text, correctKey)
        XCTAssertEqual(out["selfKey"]["signature_integrity"]["key_fingerprint"].text, "sha256:10ba682c8ad13513971e8b56881aab8bd702bb807796eca81932c735a94d6e6d")
        XCTAssertEqual(out["selfKey"]["signature_integrity"]["observed_signature_content_digest"].text, "sha256:69e56e80862a70ad9db5d6e2dee5c8f44cb3b70f39ae89a2d7f23b11bdc58536")
        // Whole-output pin (capture UUID normalized).
        let text = String(decoding: try KDNAJSON.canonical(out), as: UTF8.self)
        let normalized = text.replacingOccurrences(of: "capture:[0-9a-f-]{36}", with: "capture:UUID", options: .regularExpression)
        XCTAssertEqual(sha(Data(normalized.utf8)), "sha256:c3a9280ddab46a4479995f9ed956bae3e46a0b5719bb3ed0dc324af0be648ae8")
    }
    func testFixtureAuthorshipAndRegenerationRecord() throws {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "sections-fixture-craft-course-0.1.0.authorship", withExtension: "json", subdirectory: "Fixtures"))
        let authorship = try KDNAJSON.parse(Data(contentsOf: url))
        XCTAssertEqual(authorship["fileSha256"].text, "5f87e64fbc57637051d3bb692dc5e168e3e4328b8073d06bbfd9c1b0eb16078e")
        XCTAssertEqual(authorship["fileBytes"].numeric, 762476)
        XCTAssertEqual(authorship["retainedManifest"]["asset_id"].text, "asset:course-craft-standards")
        XCTAssertEqual(authorship["payload"]["judgments"].list.count, 8)
    }
}
