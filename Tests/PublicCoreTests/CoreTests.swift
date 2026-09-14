import XCTest
import Foundation
@testable import KDNACore

final class CoreTests: XCTestCase {
    func testAdmitsSameScaleContainers() throws {
        var results: [KDNAValue] = []
        for n in [1,20,100] {
            let url = try XCTUnwrap(Bundle.module.url(forResource: "scale-\(n)", withExtension: "kdna", subdirectory: "Fixtures"))
            let admitted = KDNACore.admitFile(url)
            XCTAssertEqual(admitted.result["status"], "accepted", "scale=\(n): \(admitted.result)")
            let snapshot = try XCTUnwrap(admitted.snapshot)
            XCTAssertEqual(snapshot.inspect()["ir"]["catalog"].list.count, n)
            results.append(["name": .string("scale-\(n)"), "result": ["status": "accepted", "data": snapshot.inspect()]])
        }
        if let output = ProcessInfo.processInfo.environment["KDNA_TEST_OUTPUT"] {
            try KDNAJSON.canonical(.array(results)).write(to: URL(fileURLWithPath: output), options: .atomic)
        }
    }
    func testExactUnicodeKeysAndStrictParsing() throws {
        let text = "{\"é\":1,\"é\":2}"
        let value = try KDNAJSON.parse(Data(text.utf8))
        XCTAssertEqual(value.fields.count, 2)
        XCTAssertThrowsError(try KDNAJSON.parse(Data("{\"a\":1,\"a\":2}".utf8)))
        XCTAssertThrowsError(try KDNAJSON.parse(Data("\"\\ud800\"".utf8)))
        XCTAssertEqual(String(data: try KDNAJSON.canonical([0, -0.0, 1e-6, 1e-7, 1e20, 1e21]), encoding: .utf8), "[0,0,0.000001,1e-7,100000000000000000000,1e+21]")
    }
}
