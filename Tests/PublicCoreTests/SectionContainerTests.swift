import XCTest
import Foundation
@testable import KDNACore

// Synthetic fixtures only; the container bytes are constructed in-code and
// mirror the canonical writer shape (flags 0x800, version-made-by 0x0314).
// Rules and diagnostic expectations follow @aikdna/kdna-core@0.36.0
// src/public-contract/section-container.js.
final class SectionContainerTests: XCTestCase {
    struct Member {
        var name: String
        var bytes: [UInt8]
        var mode: Int = 0o100644
        var method: Int = 0
        var flags: Int = 0x800
        var crc: Int?
        var declaredSize: Int?
        var declaredCompressed: Int?
        var nameOverride: [UInt8]?
        init(name: String, bytes: [UInt8], mode: Int = 0o100644, method: Int = 0, flags: Int = 0x800, crc: Int? = nil, declaredSize: Int? = nil, declaredCompressed: Int? = nil, nameOverride: [UInt8]? = nil) {
            self.name = name; self.bytes = bytes; self.mode = mode; self.method = method; self.flags = flags
            self.crc = crc; self.declaredSize = declaredSize; self.declaredCompressed = declaredCompressed; self.nameOverride = nameOverride
        }
    }
    struct Builder {
        var members: [Member] = []
        var eocdComment: [UInt8] = []
        var gapBeforeCentral = 0
        func build() -> [UInt8] {
            func le(_ value: Int, _ width: Int) -> [UInt8] { (0..<width).map { UInt8((value >> ($0 * 8)) & 0xff) } }
            var out: [UInt8] = [], central: [UInt8] = []
            for member in members {
                let nameBytes = member.nameOverride ?? Array(member.name.utf8)
                let crc = member.crc ?? Int(PublicContainer.crc(member.bytes))
                let size = member.declaredSize ?? member.bytes.count
                let compressed = member.declaredCompressed ?? member.bytes.count
                let local = out.count
                out += le(0x04034b50, 4) + le(20, 2) + le(member.flags, 2) + le(member.method, 2) + le(0, 4)
                out += le(crc, 4) + le(compressed, 4) + le(size, 4) + le(nameBytes.count, 2) + le(0, 2)
                out += nameBytes + member.bytes
                central += le(0x02014b50, 4) + le(0x0314, 2) + le(20, 2) + le(member.flags, 2) + le(member.method, 2) + le(0, 4)
                central += le(crc, 4) + le(compressed, 4) + le(size, 4)
                central += le(nameBytes.count, 2) + le(0, 4) + le(0, 4) + le(member.mode << 16, 4) + le(local, 4) + nameBytes
            }
            out += [UInt8](repeating: 0, count: gapBeforeCentral)
            let centralStart = out.count
            out += central
            out += le(0x06054b50, 4) + le(0, 4) + le(members.count, 2) + le(members.count, 2)
            out += le(central.count, 4) + le(centralStart, 4) + le(eocdComment.count, 2) + eocdComment
            return out
        }
    }
    func mimetype() -> Member { Member(name: "mimetype", bytes: Array("application/vnd.kdna.asset".utf8)) }
    func kdnaJson(_ text: String = "{}") -> Member { Member(name: "kdna.json", bytes: Array(text.utf8)) }
    func failureCode(_ bytes: [UInt8], file: StaticString = #filePath, line: UInt = #line) -> String? {
        do { _ = try SectionContainer.parse(Data(bytes)); return nil }
        catch let failure as PublicFailure { return failure.code }
        catch { return "UNEXPECTED:\(error)" }
    }
    func rejects(_ bytes: [UInt8], _ code: String, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(failureCode(bytes), code, file: file, line: line)
    }

    func testAcceptsPackShapePreservingOrderAndMode() throws {
        let pack0: [UInt8] = [0x01, 0x02, 0x03]
        let entries = try SectionContainer.parse(Data(Builder(members: [
            mimetype(), kdnaJson("{\"a\":1}"),
            Member(name: "sections/pack-0.kdnab", bytes: pack0),
            Member(name: "sections/pack-10.kdnab", bytes: [0x04], mode: 0o100755),
            Member(name: "attachments/note.bin", bytes: [], mode: 0),
        ]).build()))
        XCTAssertEqual(entries.map(\.name), ["mimetype", "kdna.json", "sections/pack-0.kdnab", "sections/pack-10.kdnab", "attachments/note.bin"])
        XCTAssertEqual(entries[2].bytes, pack0)
        XCTAssertEqual(entries[3].mode, 0o100755)
        XCTAssertEqual(entries[4].mode, 0)
    }

    func testPackOrdinalDigitsRule() {
        XCTAssertEqual(SectionContainer.packOrdinalDigits("sections/pack-0.kdnab"), "0")
        XCTAssertEqual(SectionContainer.packOrdinalDigits("sections/pack-10.kdnab"), "10")
        let long = String(repeating: "9", count: 30)
        XCTAssertEqual(SectionContainer.packOrdinalDigits("sections/pack-\(long).kdnab"), long)
        for name in ["sections/pack-01.kdnab", "sections/pack-.kdnab", "sections/pack-1.kdna", "sections/pack-1.kdnabx", "sections/pack-1.KDNAB", "sections/pack-1.kdnab\u{2028}", "sections/pack-a.kdnab", "payload.kdnab"] {
            XCTAssertNil(SectionContainer.packOrdinalDigits(name), name)
        }
    }

    func testPackNameAllowlist() {
        for name in ["sections/pack-0.kdnab", "sections/pack-10.kdnab", "sections/pack-\(String(repeating: "9", count: 30)).kdnab"] {
            let code = failureCode(Builder(members: [mimetype(), kdnaJson(), Member(name: name, bytes: [0x00])]).build())
            XCTAssertNil(code, name)
        }
        for name in ["sections/pack-01.kdnab", "sections/pack-.kdnab", "sections/pack-1.kdna", "sections/pack-1.KDNAB", "sections/other.kdnab", "sections/pack-1.kdnab\u{2028}", "payload.kdnab", "notes.txt", "attachments/"] {
            rejects(Builder(members: [mimetype(), kdnaJson(), Member(name: name, bytes: [0x00])]).build(), "READ_CORE_INVALID")
        }
    }

    func testDuplicateAndLegacyPayloadRules() {
        rejects(Builder(members: [mimetype(), kdnaJson(), Member(name: "payload.kdnab", bytes: [0x00])]).build(), "READ_CORE_INVALID")
        rejects(Builder(members: [mimetype(), kdnaJson(), kdnaJson("{}")]).build(), "READ_CORE_INVALID")
    }

    func testEocdCommentAcceptedAndGapRejected() {
        XCTAssertNil(failureCode(Builder(members: [mimetype(), kdnaJson()], eocdComment: [0x61, 0x62]).build()))
        rejects(Builder(members: [mimetype(), kdnaJson()], gapBeforeCentral: 1).build(), "READ_CORE_INVALID")
    }

    func testStoredMethodRuleAndCapabilityMapping() {
        rejects(Builder(members: [mimetype(), kdnaJson(), Member(name: "sections/pack-0.kdnab", bytes: [0xde, 0xad], method: 8)]).build(), "READ_CORE_INVALID")
        rejects(Builder(members: [mimetype(), Member(name: "kdna.json", bytes: [0xde, 0xad], method: 8)]).build(), "READ_CORE_CAPABILITY_UNAVAILABLE")
        rejects(Builder(members: [mimetype(), Member(name: "kdna.json", bytes: [0x00], method: 9)]).build(), "READ_CORE_CAPABILITY_UNAVAILABLE")
        rejects(Builder(members: [Member(name: "mimetype", bytes: [0xde, 0xad], method: 8), kdnaJson()]).build(), "READ_CORE_CAPABILITY_UNAVAILABLE")
    }

    func testMimetypeValueAndPositionRules() {
        rejects(Builder(members: [Member(name: "mimetype", bytes: Array("application/vnd.kdna.asset!".utf8)), kdnaJson()]).build(), "READ_CORE_INVALID")
        rejects(Builder(members: [Member(name: "mimetype", bytes: [0xff]), kdnaJson()]).build(), "READ_CORE_CAPABILITY_UNAVAILABLE")
        rejects(Builder(members: [kdnaJson(), mimetype()]).build(), "READ_CORE_INVALID")
    }

    func testKdnaJsonPresenceOnly() {
        XCTAssertNil(failureCode(Builder(members: [mimetype(), kdnaJson("")]).build()))
        rejects(Builder(members: [mimetype(), Member(name: "sections/pack-0.kdnab", bytes: [0x00])]).build(), "READ_CORE_INVALID")
    }

    func testCrcFlagAndModeGates() {
        rejects(Builder(members: [mimetype(), Member(name: "kdna.json", bytes: [0x00], crc: 7)]).build(), "READ_CORE_INVALID")
        rejects(Builder(members: [mimetype(), Member(name: "kdna.json", bytes: [0x00], flags: 0x801)]).build(), "READ_CORE_INVALID")
        XCTAssertNil(failureCode(Builder(members: [mimetype(), Member(name: "kdna.json", bytes: [0x00], flags: 0)]).build()))
        rejects(Builder(members: [mimetype(), Member(name: "kdna.json", bytes: [0x00], mode: 0o040755)]).build(), "READ_CORE_INVALID")
    }

    func testEntryCountLimitAndSizeGates() {
        var members = [mimetype(), kdnaJson()]
        for index in 0..<127 { members.append(Member(name: "sections/pack-\(index + 1).kdnab", bytes: [0x00])) }
        rejects(Builder(members: members).build(), "READ_CORE_INVALID")
        rejects(Builder(members: [mimetype(), Member(name: "kdna.json", bytes: [], declaredSize: SectionContainer.entryLimit + 1, declaredCompressed: SectionContainer.entryLimit + 1)]).build(), "READ_CORE_INVALID")
        rejects(Builder(members: [mimetype(), Member(name: "kdna.json", bytes: [], declaredSize: 5, declaredCompressed: 0)]).build(), "READ_CORE_INVALID")
        rejects(Builder(members: [mimetype(), Member(name: "kdna.json", bytes: [0x00], declaredSize: 101, declaredCompressed: 1)]).build(), "READ_CORE_INVALID")
    }

    func testInvalidUtf8NameClassifiesAsCapability() {
        rejects(Builder(members: [mimetype(), kdnaJson(), Member(name: "x", bytes: [0x00], nameOverride: [0x73, 0xff])]).build(), "READ_CORE_CAPABILITY_UNAVAILABLE")
    }
}
