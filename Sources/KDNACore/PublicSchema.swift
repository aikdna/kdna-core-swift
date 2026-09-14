import Foundation

/// Evaluates only the keyword set present in the SHA-pinned public source.
/// Schema resources are mechanical mirrors, never an independently edited rule set.
enum PublicSchema {
    static let resourceSHA = "ec8a2616a768f5523e8852487e757f6f9560d1933ea3a9ee90ead69fe1120f4d"
    static func contract() throws -> J {
        guard let url = Bundle.module.url(forResource: "generated-contract", withExtension: "json", subdirectory: "Schemas") else { throw PublicFailure("READ_CORE_CAPABILITY_UNAVAILABLE") }
        let data = try Data(contentsOf: url)
        try demand(sha(data) == "sha256:" + resourceSHA, "READ_CORE_CAPABILITY_UNAVAILABLE")
        let c = try KDNAJSON.parse(data)
        for s in c["types"].fields.values { try checkKeywords(s) }
        return c
    }
    static let keywords: Set<String> = ["$ref", "type", "enum", "const", "properties", "required", "additionalProperties", "items", "minItems", "maxItems", "uniqueItems", "minLength", "maxLength", "pattern", "minimum", "maximum", "minProperties", "allOf", "anyOf", "oneOf", "not", "if", "then"]
    static func checkKeywords(_ s: J) throws {
        if case .bool = s { return }
        try demand(s.fields.keys.allSatisfy { keywords.contains($0.text) }, "READ_CORE_CAPABILITY_UNAVAILABLE")
        for k in ["allOf", "anyOf", "oneOf"] { for child in s[k].list { try checkKeywords(child) } }
        for k in ["items", "not", "if", "then", "additionalProperties"] where s.has(k) { try checkKeywords(s[k]) }
        for child in s["properties"].fields.values { try checkKeywords(child) }
    }
    static func typeMatches(_ v: J, _ kind: String) -> Bool {
        switch (v, kind) {
        case (.null, "null"), (.bool, "boolean"), (.string, "string"), (.object, "object"), (.array, "array"): return true
        case (.number(let n), "number"): return n.isFinite
        case (.number(let n), "integer"): return n.isFinite && n.rounded(.towardZero) == n
        default: return false
        }
    }
    static func matches(_ v: J, _ s: J, _ types: J, _ depth: Int = 0) -> Bool {
        if depth > 256 { return false }
        if case .bool(let x) = s { return x }
        if s.has("$ref") {
            let ref = s["$ref"].text
            if !ref.hasPrefix("#/$defs/") || !types.has(String(ref.dropFirst(8))) { return false }
            if !matches(v, types[String(ref.dropFirst(8))], types, depth + 1) { return false }
        }
        if s.has("type") && !typeMatches(v, s["type"].text) { return false }
        if s.has("const") && v != s["const"] { return false }
        if s.has("enum") && !s["enum"].list.contains(v) { return false }
        if case .number(let n) = v {
            if s.has("minimum") && n < s["minimum"].numeric { return false }
            if s.has("maximum") && n > s["maximum"].numeric { return false }
        }
        if case .string(let text) = v {
            let count = Double(text.unicodeScalars.count)
            if s.has("minLength") && count < s["minLength"].numeric || s.has("maxLength") && count > s["maxLength"].numeric { return false }
            if s.has("pattern") {
                if s["pattern"].text == "\\S" {
                    let whitespace: Set<UInt32> = [9,10,11,12,13,32,160,5760,8192,8193,8194,8195,8196,8197,8198,8199,8200,8201,8202,8232,8233,8239,8287,12288,65279]
                    if !text.unicodeScalars.contains(where: { !whitespace.contains($0.value) }) { return false }
                } else if text.range(of: s["pattern"].text, options: .regularExpression) == nil { return false }
            }
        }
        if case .object(let object) = v {
            if s["required"].list.contains(where: { object[KDNAKey($0.text)] == nil }) { return false }
            if s.has("minProperties") && Double(object.count) < s["minProperties"].numeric { return false }
            let props = s["properties"]
            for (key, value) in object {
                let child = props.has(key.text) ? props[key.text] : s.has("additionalProperties") ? s["additionalProperties"] : true
                if !matches(value, child, types, depth + 1) { return false }
            }
        }
        if case .array(let items) = v {
            if s.has("minItems") && Double(items.count) < s["minItems"].numeric || s.has("maxItems") && Double(items.count) > s["maxItems"].numeric { return false }
            if s["uniqueItems"].boolean {
                for i in items.indices { if items[..<i].contains(items[i]) { return false } }
            }
            if s.has("items") && !items.allSatisfy({ matches($0, s["items"], types, depth + 1) }) { return false }
        }
        if s["allOf"].list.contains(where: { !matches(v, $0, types, depth + 1) }) { return false }
        if s.has("anyOf") && !s["anyOf"].list.contains(where: { matches(v, $0, types, depth + 1) }) { return false }
        if s.has("oneOf") && s["oneOf"].list.filter({ matches(v, $0, types, depth + 1) }).count != 1 { return false }
        if s.has("not") && matches(v, s["not"], types, depth + 1) { return false }
        if s.has("if") && matches(v, s["if"], types, depth + 1) && s.has("then") && !matches(v, s["then"], types, depth + 1) { return false }
        return true
    }
    static func timestamp(_ text: String) -> Bool {
        let pattern = "^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\\.[0-9]+)?Z$"
        guard let regex = try? NSRegularExpression(pattern: pattern), let m = regex.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)) else { return false }
        let ns = text as NSString
        let parts = (1...6).compactMap { Int(ns.substring(with: m.range(at: $0))) }
        guard parts.count == 6 else { return false }
        let y = parts[0], month = parts[1], day = parts[2]
        let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
        let days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        return (1...12).contains(month) && (1...days[month - 1]).contains(day) && parts[3] <= 23 && parts[4] <= 59 && parts[5] <= 59
    }
    static func scalars(_ v: J, _ s: J, _ types: J, _ depth: Int = 0) throws {
        try demand(depth <= 64)
        if s.has("$ref") {
            let name = String(s["$ref"].text.dropFirst(8))
            if name == "Identifier" { try demand(identifier(v)) }
            if ["EntryName", "RuntimeMandatoryEntryName"].contains(name) { try demand(validEntry(v.text)) }
            if name == "Timestamp" { try demand(timestamp(v.text)) }
            return try scalars(v, types[name], types, depth)
        }
        if case .string(let text) = v { try demand(scalar(text)) }
        if case .object = v { for (key, child) in s["properties"].fields where v.has(key.text) { try scalars(v[key.text], child, types, depth + 1) } }
        if case .array(let values) = v, s.has("items") { for value in values { try scalars(value, s["items"], types, depth + 1) } }
        for child in s["allOf"].list { try scalars(v, child, types, depth) }
        for child in (s.has("oneOf") ? s["oneOf"] : s["anyOf"]).list {
            let resolved = child.has("$ref") ? types[String(child["$ref"].text.dropFirst(8))] : child
            if resolved.has("type") && !typeMatches(v, resolved["type"].text) { continue }
            if resolved["properties"].fields.contains(where: { $0.value.has("const") && v.has($0.key.text) && v[$0.key.text] != $0.value["const"] }) { continue }
            try scalars(v, child, types, depth)
        }
    }
    static func validate(_ name: String, _ value: J, _ contract: J) throws {
        let types = contract["types"]
        try demand(matches(value, types[name], types))
        try scalars(value, types[name], types)
    }
}
