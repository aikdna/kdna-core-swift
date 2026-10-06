import XCTest
import Foundation
@testable import KDNACore

// Oracle rows for the frame decode layer (node-order-index/1 metadata,
// frame-local-ordered-scope-dictionary/1 xref frames, and the bare strict
// CBOR walk). Synthetic inputs only. Authority recorded in each fixture:
// released @aikdna/kdna-core@0.36.0 section-metadata-codec.js /
// section-scope-codec.js / cbor.js; expectations are the released verdicts —
// closed code strings verbatim, canonicalJson of the decoded value when
// accepted.
final class SectionCodecTests: XCTestCase {
    func fixture(_ name: String) throws -> J {
        let url = try XCTUnwrap(Bundle.module.url(forResource: name, withExtension: "json", subdirectory: "Fixtures"))
        return try KDNAJSON.parse(Data(contentsOf: url))
    }
    func canonical(_ value: J) -> String { String(decoding: (try? KDNAJSON.canonical(value)) ?? Data(), as: UTF8.self) }

    func testMetadataCodecOracleRows() throws {
        for row in try fixture("metadata-codec-oracles")["rows"].list {
            let outcome: String
            let decoded: String?
            do { decoded = canonical(try MetadataCodec.decode(row["stored"])); outcome = "ok" }
            catch let failure as PublicFailure { decoded = nil; outcome = failure.code }
            XCTAssertEqual(outcome, row["expected"].text, row["name"].text)
            if outcome == "ok" { XCTAssertEqual(decoded, row["value"].text, row["name"].text) }
        }
    }

    func testScopeCodecOracleRows() throws {
        for row in try fixture("scope-codec-oracles")["rows"].list {
            let outcome: String
            let decoded: String?
            do { decoded = canonical(try SectionScopeCodec.decodeFrame(row["stored"])); outcome = "ok" }
            catch let failure as PublicFailure { decoded = nil; outcome = failure.code }
            XCTAssertEqual(outcome, row["expected"].text, row["name"].text)
            if outcome == "ok" { XCTAssertEqual(decoded, row["value"].text, row["name"].text) }
        }
    }

    func testCBORFrameOracleRows() throws {
        for row in try fixture("cbor-frame-oracles")["rows"].list {
            let hex = row["bytes_hex"].text
            var bytes: [UInt8] = []
            var index = hex.startIndex
            while index < hex.endIndex {
                let next = hex.index(index, offsetBy: 2)
                bytes.append(UInt8(hex[index..<next], radix: 16)!)
                index = next
            }
            let outcome: String
            let decoded: String?
            do { var decoder = PublicCBOR(bytes: bytes); decoded = canonical(try decoder.decode()); outcome = "ok" }
            catch let failure as PublicFailure { decoded = nil; outcome = failure.code }
            XCTAssertEqual(outcome, row["expected"].text, row["name"].text)
            if outcome == "ok" { XCTAssertEqual(decoded, row["value"].text, row["name"].text) }
        }
    }
}
