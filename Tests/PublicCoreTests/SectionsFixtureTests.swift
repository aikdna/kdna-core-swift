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
    func testFixtureAuthorshipAndRegenerationRecord() throws {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "sections-fixture-craft-course-0.1.0.authorship", withExtension: "json", subdirectory: "Fixtures"))
        let authorship = try KDNAJSON.parse(Data(contentsOf: url))
        XCTAssertEqual(authorship["fileSha256"].text, "5f87e64fbc57637051d3bb692dc5e168e3e4328b8073d06bbfd9c1b0eb16078e")
        XCTAssertEqual(authorship["fileBytes"].numeric, 762476)
        XCTAssertEqual(authorship["retainedManifest"]["asset_id"].text, "asset:course-craft-standards")
        XCTAssertEqual(authorship["payload"]["judgments"].list.count, 8)
    }
}
