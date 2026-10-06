import Foundation

// The 0.6 sections container: the same ZIP structural subset as
// PublicContainer.parse, with the sections-line entry rules (packs instead
// of payload.kdnab, stored-only packs, a wider entry cap).
//
// Reference implementation: @aikdna/kdna-core@0.36.0
// src/public-contract/section-container.js (`parseSectionContainer`).
// Observable diagnostics mirror it: a rule violation rejects
// READ_CORE_INVALID; a failure raised by a raw decoder — invalid UTF-8 in
// an entry name or in the mimetype value, an inflate failure or its output
// cap, an unknown compression method — classifies as
// READ_CORE_CAPABILITY_UNAVAILABLE, matching the Node catch-all that maps
// raw zlib/TextDecoder errors (not the browser-native variant, which the
// port does not track).
enum SectionContainer {
    static let maximumBytes = 26214400
    static let entryLimit = 8388608
    static let totalLimit = 12582912
    static let ratioLimit = 100
    static let countLimit = 128

    struct Entry {
        let name: String
        let bytes: [UInt8]
        let mode: Int
    }

    // The `sections/pack-(0|[1-9][0-9]*).kdnab` rule, hand-rolled rather
    // than regex: the digit run is unbounded, so it must not be routed
    // through Int, and the rule should not depend on regex-engine anchor
    // semantics (ICU versus ECMAScript `$` differ across platforms on
    // trailing line terminators; probed equivalent on this platform today,
    // but the hand-rolled form is exact by construction). Returns the
    // ordinal digits, or nil when the name is not a well-formed pack name
    // (the caller's allowlist then rejects it unless another rule admits
    // the name).
    static func packOrdinalDigits(_ name: String) -> String? {
        let prefix = "sections/pack-", suffix = ".kdnab"
        guard name.hasPrefix(prefix), name.hasSuffix(suffix) else { return nil }
        let digits = name.dropFirst(prefix.count).dropLast(suffix.count)
        if digits == "0" { return "0" }
        guard let first = digits.first, first >= "1", first <= "9",
            digits.allSatisfy({ $0.isASCII && $0 >= "0" && $0 <= "9" }) else { return nil }
        return String(digits)
    }

    static func parse(_ data: Data) throws -> [Entry] {
        let bytes = Array(data)
        try demand(bytes.count >= 22 && bytes.count <= maximumBytes)
        func u(_ at: Int, _ width: Int) throws -> Int {
            try demand(at >= 0 && at + width <= bytes.count)
            return (0..<width).reduce(0) { $0 | Int(bytes[at + $1]) << ($1 * 8) }
        }
        var end = -1
        for i in stride(from: bytes.count - 22, through: max(0, bytes.count - 65557), by: -1) {
            if try u(i, 4) == 0x06054b50, i + 22 + (try u(i + 20, 2)) == bytes.count { end = i; break }
        }
        try demand(end >= 0)
        try demand(try u(end + 4, 2) == 0 && u(end + 6, 2) == 0 && u(end + 8, 2) == u(end + 10, 2))
        let count = try u(end + 10, 2), centralSize = try u(end + 12, 4), centralStart = try u(end + 16, 4)
        try demand(count > 0 && count <= countLimit && centralStart + centralSize == end)
        var entries: [Entry] = [], ranges: [(Int, Int)] = []
        var offset = centralStart, total = 0
        for index in 0..<count {
            try demand(try u(offset, 4) == 0x02014b50 && offset + 46 <= bytes.count)
            let flags = try u(offset + 8, 2), method = try u(offset + 10, 2), checksum = try u(offset + 16, 4)
            let compressed = try u(offset + 20, 4), size = try u(offset + 24, 4)
            let length = try u(offset + 28, 2), extra = try u(offset + 30, 2), comment = try u(offset + 32, 2)
            let mode = try u(offset + 38, 4) >> 16, local = try u(offset + 42, 4)
            try demand(offset + 46 + length + extra + comment <= bytes.count)
            let nameBytes = Array(bytes[offset + 46..<offset + 46 + length])
            guard let name = String(bytes: nameBytes, encoding: .utf8) else { throw PublicFailure("READ_CORE_CAPABILITY_UNAVAILABLE") }
            try demand(validEntry(name) && !entries.contains { $0.name == name } && flags & ~0x800 == 0 && u(offset + 34, 2) == 0)
            let type = mode & 0o170000
            try demand(type == 0 || type == 0o100000)
            try demand(["mimetype", "kdna.json", "checksums.json", "signature.kdsig"].contains(name) || packOrdinalDigits(name) != nil || name.hasPrefix("attachments/"))
            try demand(!(name.hasPrefix("sections/") && method != 0))
            total += size
            try demand(size <= entryLimit && !(compressed == 0 && size != 0) && !(compressed > 0 && size > compressed * ratioLimit) && total <= totalLimit)
            try demand(try u(local, 4) == 0x04034b50 && u(local + 6, 2) == flags && u(local + 8, 2) == method && u(local + 14, 4) == checksum && u(local + 18, 4) == compressed && u(local + 22, 4) == size && u(local + 26, 2) == length)
            let start = local + 30 + length + (try u(local + 28, 2))
            try demand(local + 30 + length <= bytes.count && start + compressed <= bytes.count && start + compressed <= centralStart)
            try demand(!ranges.contains { local < $0.1 && start + compressed > $0.0 })
            try demand(bytes[local + 30..<local + 30 + length].elementsEqual(nameBytes))
            ranges.append((local, start + compressed))
            let encoded = Array(bytes[start..<start + compressed])
            let decoded: [UInt8]
            if method == 0 { decoded = encoded }
            else if method == 8 {
                do { decoded = try PublicContainer.decompress(encoded, maximum: entryLimit) }
                catch { throw PublicFailure("READ_CORE_CAPABILITY_UNAVAILABLE") }
            } else { throw PublicFailure("READ_CORE_CAPABILITY_UNAVAILABLE") }
            try demand(decoded.count == size && PublicContainer.crc(decoded) == UInt32(checksum))
            if index == 0 { try demand(name == "mimetype" && local == 0 && method == 0) }
            entries.append(Entry(name: name, bytes: decoded, mode: mode))
            offset += 46 + length + extra + comment
        }
        var physicalEnd = 0
        for range in ranges.sorted(by: { $0.0 < $1.0 }) { try demand(range.0 == physicalEnd); physicalEnd = range.1 }
        try demand(physicalEnd == centralStart && offset == end)
        guard let mimetype = entries.first?.bytes else { throw PublicFailure("READ_CORE_INVALID") }
        guard let text = String(bytes: mimetype, encoding: .utf8) else { throw PublicFailure("READ_CORE_CAPABILITY_UNAVAILABLE") }
        try demand(text == "application/vnd.kdna.asset" && entries.contains { $0.name == "kdna.json" })
        return entries
    }
}
