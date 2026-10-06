import XCTest
import Foundation
@testable import KDNACore

// Oracle rows for the sections digest set. Synthetic entry sets only;
// authority recorded in the fixture (released @aikdna/kdna-core@0.36.0
// section-digests.js observeE + digests.js contentTreePreimage).
final class SectionDigestsTests: XCTestCase {
    func fixture() throws -> J {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "sections-digests-oracles", withExtension: "json", subdirectory: "Fixtures"))
        return try KDNAJSON.parse(Data(contentsOf: url))
    }
    func bytes(_ hex: String) -> [UInt8] {
        var out: [UInt8] = [], index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            out.append(UInt8(hex[index..<next], radix: 16)!)
            index = next
        }
        return out
    }
    func entries(_ row: J) -> [SectionContainer.Entry] {
        row["members"].list.map { SectionContainer.Entry(name: $0["name"].text, bytes: bytes($0["bytes_hex"].text), mode: 0) }
    }

    func testObserveE() throws {
        for row in try fixture()["e_rows"].list {
            let manifest: J = ["runtime": row["runtime"]]
            let packNames = row["pack_names"].list.map { $0.text }
            do {
                let result = try SectionDigests.observeE(entries(row), manifest, packNames)
                XCTAssertEqual("ok", row["expected"].text, row["name"].text)
                XCTAssertEqual(result["digest"].text, row["digest"].text, row["name"].text)
                XCTAssertEqual(result["member_names"].list.map { $0.text }, row["member_names"].list.map { $0.text }, row["name"].text)
                XCTAssertEqual(result["profile"].text, "kdna.digest-basis.runtime-entry-set/0.3.0-candidate")
            } catch let failure as PublicFailure {
                XCTAssertEqual(failure.code, row["expected"].text, row["name"].text)
            }
        }
    }

    func testContentTreePreimage() throws {
        for row in try fixture()["c_rows"].list {
            let map = Dictionary(uniqueKeysWithValues: row["entries"].list.map { (KDNAKey($0["name"].text), Data(bytes($0["bytes_hex"].text))) })
            do {
                let digest = sha(try PublicDigests.content(map))
                XCTAssertEqual("ok", row["expected"].text, row["name"].text)
                XCTAssertEqual(digest, row["digest"].text, row["name"].text)
            } catch let failure as PublicFailure {
                XCTAssertEqual(failure.code, row["expected"].text, row["name"].text)
            }
        }
    }
}
