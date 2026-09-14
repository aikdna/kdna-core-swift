import XCTest
import Foundation
@testable import KDNACore

final class ParityTests: XCTestCase {
    func testSameRealCoreContainersAsPD275Node() throws {
        let input = try XCTUnwrap(Bundle.module.url(forResource: "current-fresh-node-core", withExtension: "json", subdirectory: "Fixtures"))
        let rows = try KDNAJSON.parse(Data(contentsOf: input)).list
        var results: [KDNAValue] = []
        func normalize(_ value: KDNAValue) throws -> String {
            String(decoding: try KDNAJSON.canonical(value), as: UTF8.self)
                .replacingOccurrences(of: "snapshot:[0-9a-f-]{36}", with: "snapshot:00000000-0000-0000-0000-000000000000", options: .regularExpression)
        }
        for row in rows {
            let file = row["file"].text
            let url = try XCTUnwrap(Bundle.module.url(forResource: String(file.dropLast(5)), withExtension: "kdna", subdirectory: "Fixtures"))
            let admission = KDNACore.admitFile(url)
            let actual: KDNAValue
            if let snapshot = admission.snapshot { actual = ["status":"accepted", "data":snapshot.inspect()] }
            else { actual = admission.result }
            let actualText = try normalize(actual), expectedText = try normalize(row["result"])
            let matched = actualText == expectedText
            XCTAssertTrue(matched, row["name"].text + "\nACTUAL\n" + actualText + "\nEXPECTED\n" + expectedText)
            results.append(["name":row["name"], "matched":.bool(matched), "actual":actual, "expected":row["result"]])
        }
        if let output = ProcessInfo.processInfo.environment["KDNA_PARITY_OUTPUT"] {
            try KDNAJSON.canonical(.array(results)).write(to: URL(fileURLWithPath: output), options: .atomic)
        }
    }
}
