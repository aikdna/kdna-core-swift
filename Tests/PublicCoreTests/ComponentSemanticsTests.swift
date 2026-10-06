import XCTest
import Foundation
@testable import KDNACore

// Oracle rows for the component-semantics traversal surface (synthetic
// micro-payloads; authority: released @aikdna/kdna-core@0.36.0
// component-semantics.js visitExtensions / checkInterpretationComplete).
// The JS walk dedups by object identity; strict JSON inputs carry no
// aliasing, so the port's per-path dedup is exact for every representable
// input.
final class ComponentSemanticsTests: XCTestCase {
    func testVisitExtensionsOracleRows() throws {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "visit-extensions-oracles", withExtension: "json", subdirectory: "Fixtures"))
        let fixture = try KDNAJSON.parse(Data(contentsOf: url))
        for row in fixture["rows"].list {
            let payload = row["payload"]
            if row["name"].text.hasPrefix("interpretation-complete") {
                let outcome: String
                do { try ComponentSemantics.checkInterpretationComplete(payload); outcome = "ok" }
                catch let failure as PublicFailure { outcome = failure.code }
                XCTAssertEqual(outcome, row["expected"].text, row["name"].text)
                continue
            }
            var paths: [String] = []
            let verdict: String
            do {
                try ComponentSemantics.visitExtensions(payload) { extensionValue, path in
                    let rendered = path.map { element -> String in
                        if case .index(let position) = element { return "#\(position)" }
                        if case .key(let key) = element { return key }
                        return "?"
                    }.joined(separator: "/")
                    paths.append(rendered + "=" + String(decoding: try KDNAJSON.canonical(extensionValue["id"]), as: UTF8.self))
                }
                verdict = "ok"
            } catch let failure as PublicFailure { verdict = failure.code }
            XCTAssertEqual(verdict, row["expected"].text, row["name"].text)
            XCTAssertEqual(paths, row["paths"].list.map { $0.text }, row["name"].text)
        }
    }
}
