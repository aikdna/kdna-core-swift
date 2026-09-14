import XCTest
import Foundation
@testable import KDNACore

final class JSONAdmissionTests: XCTestCase {
    func testFrozenEncodingAndGrammarExpectations() throws {
        let resource = try XCTUnwrap(Bundle.module.url(forResource: "current-json-admission-node-frozen", withExtension: "json", subdirectory: "Fixtures"))
        let cases = try KDNAJSON.parse(Data(contentsOf: resource)).list
        var output: [KDNAValue] = []
        func normalize(_ value: KDNAValue) throws -> String {
            String(decoding: try KDNAJSON.canonical(value), as: UTF8.self)
                .replacingOccurrences(of: "snapshot:[0-9a-f-]{36}", with: "snapshot:00000000-0000-0000-0000-000000000000", options: .regularExpression)
        }
        for row in cases {
            let file = row["file"].text
            let url = try XCTUnwrap(Bundle.module.url(forResource: String(file.dropLast(5)), withExtension: "kdna", subdirectory: "Fixtures"))
            let admitted = KDNACore.admitFile(url)
            let actual: KDNAValue
            if let snapshot = admitted.snapshot { actual = ["status":"accepted", "data":snapshot.inspect()] }
            else { actual = admitted.result }
            let actualText = try normalize(actual), expectedText = try normalize(row["result"])
            let match = actualText == expectedText
            XCTAssertTrue(match, row["name"].text + "\n" + actualText + "\nEXPECTED\n" + expectedText)
            output.append(["name":row["name"], "matched":.bool(match), "actual":actual, "expected":row["result"]])
        }
        if let target = ProcessInfo.processInfo.environment["KDNA_JSON_OUTPUT"] {
            try KDNAJSON.canonical(.array(output)).write(to: URL(fileURLWithPath: target), options: .atomic)
        }
    }
}
