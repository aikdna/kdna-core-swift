import XCTest
import Foundation
import KDNACore

final class NumberTests: XCTestCase {
    func testBinary64CanonicalSpellingAgainstNode() throws {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "number-oracle", withExtension: "json", subdirectory: "Fixtures"))
        let rows = try KDNAJSON.parse(Data(contentsOf: url)).list
        XCTAssertEqual(rows.count, 2066)
        for row in rows {
            let bits = try XCTUnwrap(UInt64(row["bits"].text, radix: 16))
            let actual = String(data: try KDNAJSON.canonical(.number(Double(bitPattern: bits))), encoding: .utf8)
            XCTAssertEqual(actual, row["expected"].text, row["bits"].text)
        }
    }
}
