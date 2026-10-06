import XCTest
import Foundation
@testable import KDNACore

// Oracle rows for the 0.5-generation R2 value shapes (synthetic shapes and
// values; authority: released @aikdna/kdna-core@0.36.0 r2-values.js).
final class R2ValuesTests: XCTestCase {
    func run(_ fn: String, _ args: [J]) throws {
        switch fn {
        case "unique": _ = try R2Values.unique(args[0].list)
        case "bounds": try R2Values.bounds(args[0])
        case "validateShape": try R2Values.validateShape(args[0])
        case "resultShape": try R2Values.resultShape(args[0], args[1])
        case "validateContract": try R2Values.validateContract(args[0])
        case "valueFor": try R2Values.valueFor(args[0], args[1])
        case "validateResult": try R2Values.validateResult(args[0])
        case "shapeAt": _ = try R2Values.shapeAt(args[0], args[1].list.map { $0.text })
        case "compatible": try R2Values.compatible(args[0], args[1])
        case "projected": _ = try R2Values.projected(args[0], args[1].list.map { $0.text })
        case "completeBindings": try R2Values.completeBindings(args[0], args[1].list.map { $0.list.map { $0.text } })
        default: XCTFail("unknown fn \(fn)")
        }
    }
    func testR2ValuesOracleRows() throws {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "r2values-oracles", withExtension: "json", subdirectory: "Fixtures"))
        let fixture = try KDNAJSON.parse(Data(contentsOf: url))
        XCTAssertGreaterThan(fixture["rows"].list.count, 40)
        for row in fixture["rows"].list {
            let fn = row["fn"].text
            do {
                try run(fn, row["args"].list)
                XCTAssertEqual("ok", row["expected"].text, row["name"].text)
            } catch let failure as PublicFailure {
                XCTAssertEqual(failure.code, row["expected"].text, row["name"].text)
            }
        }
    }
}
