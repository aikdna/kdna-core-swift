import Foundation
import zlib

enum PublicContainer {
    static let maximumBytes = 26214400
    static let entryLimit = 5242880
    static func crc(_ bytes: [UInt8]) -> UInt32 {
        var n: UInt32 = 0xffffffff
        for byte in bytes {
            n ^= UInt32(byte)
            for _ in 0..<8 { n = (n >> 1) ^ (n & 1 == 1 ? 0xedb88320 : 0) }
        }
        return n ^ 0xffffffff
    }
    static func decompress(_ bytes: [UInt8]) throws -> [UInt8] {
        var stream = z_stream()
        try demand(inflateInit2_(&stream, -MAX_WBITS, zlibVersion(), Int32(MemoryLayout<z_stream>.size)) == Z_OK, "READ_CORE_CAPABILITY_UNAVAILABLE")
        defer { inflateEnd(&stream) }
        var output = [UInt8](repeating: 0, count: entryLimit + 1)
        let result = bytes.withUnsafeBufferPointer { input in
            output.withUnsafeMutableBufferPointer { target in
                stream.next_in = UnsafeMutablePointer(mutating: input.baseAddress)
                stream.avail_in = uInt(input.count)
                stream.next_out = target.baseAddress
                stream.avail_out = uInt(target.count)
                return inflate(&stream, Z_FINISH)
            }
        }
        try demand(result == Z_STREAM_END && stream.total_out <= entryLimit)
        return Array(output.prefix(Int(stream.total_out)))
    }
    static func parse(_ data: Data) throws -> [KDNAKey: Data] {
        let bytes = Array(data)
        try demand(bytes.count >= 22 && bytes.count <= maximumBytes)
        func u(_ at: Int, _ width: Int) throws -> Int {
            try demand(at >= 0 && at + width <= bytes.count)
            return (0..<width).reduce(0) { $0 | Int(bytes[at + $1]) << ($1 * 8) }
        }
        var end = -1
        for i in stride(from: bytes.count - 22, through: max(0, bytes.count - 65557), by: -1) {
            if try u(i, 4) == 0x06054b50 && i + 22 + u(i + 20, 2) == bytes.count { end = i; break }
        }
        try demand(end >= 0)
        try demand(u(end + 4, 2) == 0 && u(end + 6, 2) == 0 && u(end + 8, 2) == u(end + 10, 2))
        let count = try u(end + 10, 2), centralSize = try u(end + 12, 4), centralStart = try u(end + 16, 4)
        try demand(count > 0 && count <= 128 && centralStart + centralSize == end)
        var entries: [KDNAKey:Data] = [:], ranges: [(Int,Int)] = []
        var offset = centralStart, total = 0
        for index in 0..<count {
            try demand(u(offset, 4) == 0x02014b50 && offset + 46 <= bytes.count)
            let flags = try u(offset + 8, 2), method = try u(offset + 10, 2), checksum = try u(offset + 16, 4)
            let compressed = try u(offset + 20, 4), size = try u(offset + 24, 4)
            let length = try u(offset + 28, 2), extra = try u(offset + 30, 2), comment = try u(offset + 32, 2)
            let mode = try u(offset + 38, 4) >> 16, local = try u(offset + 42, 4)
            try demand(offset + 46 + length + extra + comment <= bytes.count)
            let nameBytes = Array(bytes[offset + 46..<offset + 46 + length])
            guard let name = String(bytes: nameBytes, encoding: .utf8) else { throw PublicFailure() }
            let key = KDNAKey(name)
            try demand(validEntry(name) && entries[key] == nil && flags & ~0x800 == 0 && u(offset + 34, 2) == 0)
            try demand(mode & 0o170000 == 0 || mode & 0o170000 == 0o100000)
            try demand(["mimetype", "kdna.json", "payload.kdnab", "checksums.json", "signature.kdsig"].contains(name) || name.hasPrefix("attachments/"))
            total += size
            try demand(size <= entryLimit && !(compressed == 0 && size != 0) && !(compressed > 0 && size > compressed * 100) && total <= 12582912)
            try demand(u(local, 4) == 0x04034b50 && u(local + 6, 2) == flags && u(local + 8, 2) == method && u(local + 14, 4) == checksum && u(local + 18, 4) == compressed && u(local + 22, 4) == size && u(local + 26, 2) == length)
            let start = try local + 30 + length + u(local + 28, 2)
            try demand(start + compressed <= centralStart && local + 30 + length <= bytes.count && start + compressed <= bytes.count)
            try demand(!ranges.contains { local < $0.1 && start + compressed > $0.0 })
            try demand(bytes[local + 30..<local + 30 + length].elementsEqual(nameBytes))
            ranges.append((local, start + compressed))
            let encoded = Array(bytes[start..<start + compressed])
            let decoded: [UInt8]
            if method == 0 { decoded = encoded }
            else if method == 8 { decoded = try decompress(encoded) }
            else { throw PublicFailure("READ_CORE_CAPABILITY_UNAVAILABLE") }
            try demand(decoded.count == size && crc(decoded) == UInt32(checksum))
            if index == 0 { try demand(name == "mimetype" && local == 0 && method == 0) }
            entries[key] = Data(decoded)
            offset += 46 + length + extra + comment
        }
        var physicalEnd = 0
        for range in ranges.sorted(by: { $0.0 < $1.0 }) { try demand(range.0 == physicalEnd); physicalEnd = range.1 }
        try demand(physicalEnd == centralStart && offset == end && entries["mimetype"] == Data("application/vnd.kdna.asset".utf8) && entries["kdna.json"] != nil && entries["payload.kdnab"] != nil)
        return entries
    }
}

struct PublicCBOR {
    let bytes: [UInt8]
    var at = 0, count = 0
    mutating func take(_ length: Int) throws -> [UInt8] {
        try demand(length >= 0 && at + length <= bytes.count)
        let start = at; at += length; return Array(bytes[start..<at])
    }
    mutating func argument(_ info: UInt8) throws -> UInt64 {
        if info < 24 { return UInt64(info) }
        try demand((24...27).contains(info))
        let data = try take(1 << Int(info - 24))
        let n = data.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        return n
    }
    mutating func value(_ depth: Int) throws -> J {
        count += 1; try demand(depth <= 64 && count <= 100000)
        let initial = try take(1)[0], major = initial >> 5, info = initial & 31
        if major == 0 || major == 1 {
            let n = try argument(info)
            if major == 0 {
                try demand(UInt64(exactly: Double(n)) == n)
                return .number(Double(n))
            }
            // The magnitude of -1-n must be checked before rounding. 2^64 is
            // exactly representable even though its encoded argument is not.
            if n == UInt64.max { return .number(-18446744073709551616.0) }
            let magnitude = n + 1
            try demand(UInt64(exactly: Double(magnitude)) == magnitude)
            return .number(-Double(magnitude))
        }
        if major == 2 || major == 3 {
            let length = try argument(info); try demand(length <= 1048576 && major == 3)
            guard let text = String(bytes: try take(Int(length)), encoding: .utf8) else { throw PublicFailure() }
            try demand(scalar(text)); return .string(text)
        }
        if major == 4 || major == 5 {
            let length = try argument(info); try demand(length <= 10000)
            if major == 4 { var result: [J] = []; for _ in 0..<Int(length) { result.append(try value(depth + 1)) }; return .array(result) }
            var result: [KDNAKey:J] = [:]
            for _ in 0..<Int(length) {
                let key = try value(depth + 1)
                guard case .string(let text) = key else { throw PublicFailure() }
                let k = KDNAKey(text); try demand(result[k] == nil); result[k] = try value(depth + 1)
            }
            return .object(result)
        }
        if major == 7 {
            if info == 20 { return false }; if info == 21 { return true }; if info == 22 { return nil }
            let number: Double
            if info == 25 {
                let bytes = try take(2), n = UInt16(bytes[0]) << 8 | UInt16(bytes[1])
                let sign: Double = n & 0x8000 == 0 ? 1 : -1, exponent = Int((n >> 10) & 31), fraction = Double(n & 1023)
                number = sign * (exponent == 0 ? pow(2, -14) * fraction / 1024 : exponent == 31 ? .infinity : pow(2, Double(exponent - 15)) * (1 + fraction / 1024))
            } else if info == 26 {
                let bits = try take(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }; number = Double(Float(bitPattern: bits))
            } else if info == 27 {
                let bits = try take(8).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }; number = Double(bitPattern: bits)
            } else { throw PublicFailure() }
            try demand(number.isFinite); return .number(number)
        }
        throw PublicFailure()
    }
    mutating func decode() throws -> J { let result = try value(0); try demand(at == bytes.count); return result }
}
