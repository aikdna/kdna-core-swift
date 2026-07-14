import Foundation

struct KDNAAnyCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int?

    init?(stringValue: String) {
        self.stringValue = stringValue
        self.intValue = nil
    }

    init?(intValue: Int) {
        self.stringValue = String(intValue)
        self.intValue = intValue
    }
}

func kdnaRejectUnknownKeys(
    from decoder: Decoder,
    allowed: Set<String>,
    type: String
) throws {
    let raw = try decoder.container(keyedBy: KDNAAnyCodingKey.self)
    let unknown = raw.allKeys.map(\.stringValue).filter { !allowed.contains($0) }.sorted()
    guard unknown.isEmpty else {
        throw DecodingError.dataCorrupted(DecodingError.Context(
            codingPath: decoder.codingPath,
            debugDescription: "\(type) contains unknown properties: \(unknown.joined(separator: ", "))"
        ))
    }
}

func kdnaRequire(_ condition: @autoclosure () -> Bool, from decoder: Decoder, _ message: String) throws {
    guard condition() else {
        throw DecodingError.dataCorrupted(DecodingError.Context(
            codingPath: decoder.codingPath,
            debugDescription: message
        ))
    }
}

func kdnaMatches(_ value: String, pattern: String) -> Bool {
    guard let expression = try? NSRegularExpression(pattern: pattern) else { return false }
    let range = NSRange(value.startIndex..<value.endIndex, in: value)
    return expression.firstMatch(in: value, range: range) != nil
}

func kdnaIsISODate(_ value: String) -> Bool {
    KDNAJSONFormats.isDateTime(value)
}

extension KeyedDecodingContainer {
    func kdnaDecodeOptionalNonNull<T: Decodable>(
        _ type: T.Type,
        forKey key: Key
    ) throws -> T? {
        guard contains(key) else { return nil }
        return try decode(type, forKey: key)
    }

    func kdnaDecodeRequiredNullable<T: Decodable>(
        _ type: T.Type,
        forKey key: Key
    ) throws -> T? {
        guard contains(key) else {
            throw DecodingError.keyNotFound(key, DecodingError.Context(
                codingPath: codingPath,
                debugDescription: "Required nullable property \(key.stringValue) is missing."
            ))
        }
        return try decodeIfPresent(type, forKey: key)
    }
}
