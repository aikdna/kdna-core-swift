import XCTest
import Foundation
@testable import KDNACore

final class ReadTests: XCTestCase {
    func testSameRealReadMatrixAsNode() async throws {
        let fixture = try XCTUnwrap(Bundle.module.url(forResource: "current-node-read", withExtension: "json", subdirectory: "Fixtures"))
        let cases = try KDNAJSON.parse(Data(contentsOf: fixture)).list
        var results: [KDNAValue] = []
        func normalize(_ value: KDNAValue) throws -> String {
            let raw = String(decoding: try KDNAJSON.canonical(value), as: UTF8.self)
            return raw.replacingOccurrences(of: "snapshot:[0-9a-f-]{36}", with: "snapshot:00000000-0000-0000-0000-000000000000", options: .regularExpression)
        }
        for row in cases {
            let c = row["case"], change = c["change"].text
            let control: KDNATrustedReadControlProvider? = change == "control-untrusted" ? nil : KDNATrustedReadControlProvider { ["admission_response_limit_bytes":4096] }
            let host: KDNATrustedHostReadProvider? = change == "untrusted" ? nil : KDNATrustedHostReadProvider(observe: { request,snapshot in
                if change == "throw-host" { throw NSError(domain: "Expected",code:1) }
                let v = snapshot.inspect()
                return ["host_id":"host:parity", "host_epoch":"epoch:parity", "decision_id":"decision:parity", "request_id":request["request_id"], "snapshot_id":v["snapshot_id"], "A":v["digests"]["A"]["observed"], "C":v["digests"]["C"]["observed"], "scope": change == "scope" ? [] : .array(v["ir"]["nodes"].list.map { $0["id"] }), "issued_at":900, "expires_at":change == "expired" ? 1000 : 2000, "decision":change == "deny" ? "deny" : "allow", "policy_id":"policy:parity", "current_ms":1000]
            }, deliver: change == "delivered-false" ? { _ in false } : nil)
            let file = c["file"].text
            let url = try XCTUnwrap(Bundle.module.url(forResource: String(file.dropLast(5)),withExtension:"kdna",subdirectory:"Fixtures"))
            let actual = await KDNARead.readFile(url,request:row["request"],control:control,host:host)
            let actualText = try normalize(actual), expectedText = try normalize(row["result"])
            let match = actualText == expectedText
            XCTAssertTrue(match, c["name"].text + "\n" + actualText + "\nEXPECTED\n" + expectedText)
            results.append(["case":c,"matched":.bool(match),"actual":actual,"expected":row["result"]])
        }
        if let output = ProcessInfo.processInfo.environment["KDNA_READ_TEST_OUTPUT"] {
            try KDNAJSON.canonical(.array(results)).write(to:URL(fileURLWithPath:output),options:.atomic)
        }
    }
}
