import XCTest
import Foundation
@testable import KDNACore

// Oracle rows for the cross-entry rule set (synthetic micro-payloads;
// authority: released @aikdna/kdna-core@0.36.0 cross-entry.js
// checkPayload/assertPayload — reports, field pointers and rule ids
// verbatim).
final class CrossEntryTests: XCTestCase {
    func testCrossEntryOracleRows() throws {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "crossentry-micro-oracles", withExtension: "json", subdirectory: "Fixtures"))
        let fixture = try KDNAJSON.parse(Data(contentsOf: url))
        let coreTerms = try SemanticContract.loadedContract.get()["core_terms"]
        XCTAssertGreaterThan(fixture["rows"].list.count, 20)
        for row in fixture["rows"].list {
            let payload = row["payload"]
            let report = try CrossEntry.checkPayload(payload, coreTerms)
            XCTAssertEqual(String(decoding: try KDNAJSON.canonical(report), as: UTF8.self),
                           String(decoding: try KDNAJSON.canonical(row["report"]), as: UTF8.self), row["name"].text)
            let outcome: J
            do { try CrossEntry.assertPayload(payload, coreTerms); outcome = ["status": "ok"] }
            catch let failure as PublicFailure {
                outcome = ["status": .string(failure.code), "field": failure.field.map { .string($0) } ?? .null, "rule": failure.crossEntryRule.map { .string($0) } ?? .null]
            }
            XCTAssertEqual(String(decoding: try KDNAJSON.canonical(outcome), as: UTF8.self),
                           String(decoding: try KDNAJSON.canonical(row["assert"]), as: UTF8.self), row["name"].text)
        }
    }
}
