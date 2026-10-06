import XCTest
import Foundation
@testable import KDNACore

// The 0.5.x-generation contract resource: pin, tuple, and the closed
// validation surface. Positive parity runs (reconstructed payloads of the
// eight local sections assets plus named mutations, 56 cells) are recorded
// as scratch evidence; the synthetic-positive payload fixture arrives with
// the fixture package's created asset.
final class SemanticContractTests: XCTestCase {
    func testResourcePinAndTuple() throws {
        let contract = try SemanticContract.loadedContract.get()
        XCTAssertEqual(contract["types"].fields.count, 431)
        let tuple = contract["versionTuple"]
        XCTAssertEqual(tuple["container"].text, "0.5.0")
        XCTAssertEqual(tuple["payload_profile"].text, "kdna.payload.judgment")
        XCTAssertEqual(tuple["payload_version"].text, "0.5.1")
        XCTAssertEqual(tuple["ir"].text, "kdna.canonical-ir/0.6.1")
    }

    func testRejectsMalformedPayloads() throws {
        for (name, value): (String, J) in [
            ("empty-object", [:]), ("string", "payload"), ("null", nil),
            ("wrong-profile", ["profile": "kdna.payload.other", "profile_version": "0.5.1"]),
            ("unknown-field", ["profile": "kdna.payload.judgment", "profile_version": "0.5.1", "unknown_field": 1]),
            ("non-finite", ["profile": "kdna.payload.judgment", "profile_version": "0.5.1", "count": .number(.infinity)]),
        ] {
            do {
                _ = try SemanticContract.validate("Payload", value)
                XCTFail("\(name) was accepted")
            } catch let failure as PublicFailure {
                XCTAssertEqual(failure.code, "READ_CORE_INVALID", name)
            }
        }
    }

    func testSeparationFromBundledGeneration() throws {
        // The two contract generations coexist by design: the bundled one is
        // the previous container line's; the 0.5 resource is the sections
        // chain's payload/IR generation.
        let bundled = try KDNACore.loadedContract.get()
        XCTAssertEqual(bundled["versionTuple"]["container"].text, "0.2.0")
        XCTAssertEqual(bundled["types"].fields.count, 275)
        XCTAssertEqual(try SemanticContract.loadedContract.get()["types"].fields.count, 431)
    }
}
