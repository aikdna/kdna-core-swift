import XCTest
import Foundation
@testable import KDNACore

// Run after the existing exact per-process receipt-counter regression.
final class ZZComponentTests: XCTestCase {
    func testASCIIComponentKeysExcludeLineTerminators() throws {
        let contract = try KDNACore.loadedContract.get()
        for text in ["shared", "a9-", String(repeating: "a", count: 64)] {
            XCTAssertNoThrow(try PublicSchema.validate("ComponentItemKey", .string(text), contract))
        }
        for text in ["", "Upper", "under_score", "é", String(repeating: "a", count: 65), "shared\n", "shared\r", "shared\r\n", "shared\u{2028}", "shared\u{2029}"] {
            XCTAssertThrowsError(try PublicSchema.validate("ComponentItemKey", .string(text), contract), text.debugDescription)
        }
    }
    func testRealNodeContainersAndCompleteReadBodies() async throws {
        let input = try XCTUnwrap(Bundle.module.url(forResource: "component-node-oracles", withExtension: "json", subdirectory: "Fixtures"))
        let oracle = try KDNAJSON.parse(Data(contentsOf: input))
        XCTAssertEqual(try KDNACore.componentSemanticsContract(), oracle["descriptor"])
        func normalize(_ value: KDNAValue) throws -> String {
            String(decoding: try KDNAJSON.canonical(value), as: UTF8.self)
                .replacingOccurrences(of: "snapshot:[0-9a-f-]{36}", with: "snapshot:00000000-0000-0000-0000-000000000000", options: .regularExpression)
        }
        for row in oracle["rows"].list {
            let url = try XCTUnwrap(Bundle.module.url(forResource: String(row["file"].text.dropLast(5)), withExtension: "kdna", subdirectory: "Fixtures"))
            let bytes = try Data(contentsOf: url), admission = KDNACore.admitBytes(bytes)
            let actual: J = admission.snapshot.map { ["status": "accepted", "data": $0.inspect()] } ?? admission.result
            XCTAssertEqual(try normalize(actual), try normalize(row["result"]), row["name"].text)
            let control = KDNATrustedReadControlProvider { ["admission_response_limit_bytes": 4096] }
            let host = KDNATrustedHostReadProvider { request, snapshot in
                let v = snapshot.inspect()
                return ["host_id": "synthetic", "host_epoch": "test", "decision_id": .string("decision:" + request["request_id"].text),
                    "request_id": request["request_id"], "snapshot_id": v["snapshot_id"], "A": v["digests"]["A"]["observed"], "C": v["digests"]["C"]["observed"],
                    "scope": .array(v["ir"]["nodes"].list.map { $0["id"] }), "issued_at": 1000, "expires_at": 61000, "current_ms": 1000,
                    "decision": "allow", "policy_id": "synthetic-only"]
            }
            let read = await KDNARead.readFile(url, request: row["request"], control: control, host: host), envelope = read["envelope"]
            let observed: J = ["channel": read["channel"], "status": envelope["status"], "content": envelope["content"], "states": envelope["states"], "diagnostics": envelope["diagnostics"]]
            XCTAssertEqual(try normalize(observed), try normalize(row["read"]), "Read " + row["name"].text)
        }
    }
}
