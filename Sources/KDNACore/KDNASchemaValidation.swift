import Foundation
import CryptoKit
import CoreFoundation

/// JSON Schema resources used by the Swift loader are byte-for-byte copies of
/// the canonical schemas in the KDNA Core 0.18.0 release at
/// `aikdna/kdna@fed4fc8`. Validation fails closed if a bundled resource is
/// missing or its digest changes without updating this lock. The evaluator
/// intentionally implements the complete set of JSON Schema keywords used by
/// these three pinned schemas, including local/external refs.
enum KDNACanonicalSchemas {
    static let canonicalCommit = "fed4fc86e3c8447a94e7498a795d0fcd5108595e"

    static let expectedDigests = [
        "manifest.schema.json": "86fd5d90077026b465c853843cd7bd48bb31d8d10148a14eb51cfc34f5962839",
        "payload-profile-v1.schema.json": "7c9835da3dcdc72e9d52a923ae04a93f2a96d0c9a7f877304a4893aa61ab9e66",
        "load-contract.schema.json": "1b262a02f3c63ec25c72ae6dc79c4a472325414d4b06c6fa3f85f56998178ebb",
    ]

    static func validateManifest(_ instance: Any) -> [String] {
        validate(instance, against: "manifest.schema.json")
    }

    static func validatePayload(_ instance: Any) -> [String] {
        validate(instance, against: "payload-profile-v1.schema.json")
    }

    static func validateLoadContract(_ instance: Any) -> [String] {
        validate(instance, against: "load-contract.schema.json")
    }

    static func resourceData(named name: String) throws -> Data {
        guard expectedDigests[name] != nil else {
            throw ResourceError("schema resource is not pinned: \(name)")
        }
        let parts = name.split(separator: ".", omittingEmptySubsequences: false)
        let resource = parts.dropLast().joined(separator: ".")
        guard let url = Bundle.module.url(
            forResource: resource,
            withExtension: "json",
            subdirectory: "Schemas"
        ) else {
            throw ResourceError("schema resource is missing: \(name)")
        }
        let data = try Data(contentsOf: url)
        let actual = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        guard actual == expectedDigests[name] else {
            throw ResourceError("schema resource digest mismatch: \(name)")
        }
        return data
    }

    private static func validate(_ instance: Any, against name: String) -> [String] {
        do {
            var documents: [String: Any] = [:]
            for resourceName in expectedDigests.keys.sorted() {
                documents[resourceName] = try JSONSerialization.jsonObject(
                    with: resourceData(named: resourceName)
                )
            }
            guard let root = documents[name] else {
                return ["$: schema resource is missing: \(name)"]
            }
            return KDNAJSONSchemaEvaluator(documents: documents).validate(
                instance,
                schema: root,
                document: name,
                path: "$"
            )
        } catch {
            return ["$: canonical schema resources unavailable: \(error.localizedDescription)"]
        }
    }

    private struct ResourceError: LocalizedError {
        let message: String
        init(_ message: String) { self.message = message }
        var errorDescription: String? { message }
    }
}

enum KDNAJSONFormats {
    /// Matches the full `ajv-formats` RFC 3339 date-time validator used by the
    /// canonical Node schema tests, including its case-insensitive T/Z and
    /// exact ECMAScript whitespace separator behavior. Foundation/ICU `\s`
    /// differs from JavaScript (notably for U+0085 and U+FEFF), so separator
    /// recognition is deliberately scalar-based.
    static func isDateTime(_ value: String) -> Bool {
        let scalars = value.unicodeScalars
        var separatorIndex: String.UnicodeScalarView.Index?
        for index in scalars.indices {
            let scalar = scalars[index]
            guard scalar == "T" || scalar == "t" || isECMAScriptWhitespace(scalar) else { continue }
            guard separatorIndex == nil else { return false }
            separatorIndex = index
        }
        guard let separatorIndex else { return false }
        let timeStart = scalars.index(after: separatorIndex)
        return isDate(String(scalars[..<separatorIndex])) &&
            isTime(String(scalars[timeStart...]))
    }

    /// Matches the full `ajv-formats` URI expression rather than Foundation's
    /// permissive URL parser. AJV additionally requires at least `/` or `:`.
    static func isURI(_ value: String) -> Bool {
        // The canonical RFC 3986 expression is ASCII-only. ICU's
        // case-insensitive matching and Unicode digit classes otherwise admit
        // values that ECMAScript/AJV rejects (for example K or full-width
        // digits), so reject non-ASCII scalars before entering the regex.
        guard value.unicodeScalars.allSatisfy({ $0.value <= 0x7F }) else { return false }
        guard value.contains("/") || value.contains(":") else { return false }
        let pattern = #"^(?:[a-z][a-z0-9+\-.]*:)(?:\/?\/(?:(?:[a-z0-9\-._~!$&'()*+,;=:]|%[0-9a-f]{2})*@)?(?:\[(?:(?:(?:(?:[0-9a-f]{1,4}:){6}|::(?:[0-9a-f]{1,4}:){5}|(?:[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:){4}|(?:(?:[0-9a-f]{1,4}:){0,1}[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:){3}|(?:(?:[0-9a-f]{1,4}:){0,2}[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:){2}|(?:(?:[0-9a-f]{1,4}:){0,3}[0-9a-f]{1,4})?::[0-9a-f]{1,4}:|(?:(?:[0-9a-f]{1,4}:){0,4}[0-9a-f]{1,4})?::)(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))|(?:(?:[0-9a-f]{1,4}:){0,5}[0-9a-f]{1,4})?::[0-9a-f]{1,4}|(?:(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4})?::)|[Vv][0-9a-f]+\.[a-z0-9\-._~!$&'()*+,;=:]+)\]|(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[a-z0-9\-._~!$&'()*+,;=]|%[0-9a-f]{2})*)(?::[0-9]*)?(?:\/(?:[a-z0-9\-._~!$&'()*+,;=:@]|%[0-9a-f]{2})*)*|\/(?:(?:[a-z0-9\-._~!$&'()*+,;=:@]|%[0-9a-f]{2})+(?:\/(?:[a-z0-9\-._~!$&'()*+,;=:@]|%[0-9a-f]{2})*)*)?|(?:[a-z0-9\-._~!$&'()*+,;=:@]|%[0-9a-f]{2})+(?:\/(?:[a-z0-9\-._~!$&'()*+,;=:@]|%[0-9a-f]{2})*)*)(?:\?(?:[a-z0-9\-._~!$&'()*+,;=:@/?]|%[0-9a-f]{2})*)?(?:#(?:[a-z0-9\-._~!$&'()*+,;=:@/?]|%[0-9a-f]{2})*)?$"#
        guard let expression = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else {
            return false
        }
        let range = NSRange(value.startIndex..<value.endIndex, in: value)
        return expression.firstMatch(in: value, range: range)?.range == range
    }

    private static func isECMAScriptWhitespace(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.value {
        case 0x0009...0x000D, 0x0020, 0x00A0, 0x1680,
             0x2000...0x200A, 0x2028, 0x2029, 0x202F, 0x205F,
             0x3000, 0xFEFF:
            return true
        default:
            return false
        }
    }

    private static func isDate(_ value: String) -> Bool {
        guard let captures = captures(#"^([0-9]{4})-([0-9]{2})-([0-9]{2})$"#, value),
              let year = Int(captures[0]),
              let month = Int(captures[1]),
              let day = Int(captures[2]),
              (1...12).contains(month) else { return false }
        let days = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        let leap = year.isMultiple(of: 4) && (!year.isMultiple(of: 100) || year.isMultiple(of: 400))
        let maximum = month == 2 && leap ? 29 : days[month]
        return (1...maximum).contains(day)
    }

    private static func isTime(_ value: String) -> Bool {
        let pattern = #"^([0-9]{2}):([0-9]{2}):([0-9]{2}(?:\.[0-9]+)?)(z|([+-])([0-9]{2})(?::?([0-9]{2}))?)?$"#
        guard let captures = captures(pattern, value, options: [.caseInsensitive]),
              let hour = Int(captures[0]),
              let minute = Int(captures[1]),
              let second = Double(captures[2]),
              !captures[3].isEmpty else { return false }
        let sign = captures[4] == "-" ? -1 : 1
        let zoneHour = Int(captures[5]) ?? 0
        let zoneMinute = Int(captures[6]) ?? 0
        guard zoneHour <= 23, zoneMinute <= 59 else { return false }
        if hour <= 23, minute <= 59, second < 60 { return true }
        let utcMinute = minute - zoneMinute * sign
        let utcHour = hour - zoneHour * sign - (utcMinute < 0 ? 1 : 0)
        return (utcHour == 23 || utcHour == -1) &&
            (utcMinute == 59 || utcMinute == -1) && second < 61
    }

    private static func captures(
        _ pattern: String,
        _ value: String,
        options: NSRegularExpression.Options = []
    ) -> [String]? {
        guard let expression = try? NSRegularExpression(pattern: pattern, options: options) else { return nil }
        let fullRange = NSRange(value.startIndex..<value.endIndex, in: value)
        guard let match = expression.firstMatch(in: value, range: fullRange), match.range == fullRange else {
            return nil
        }
        return (1..<match.numberOfRanges).map { index in
            let range = match.range(at: index)
            guard range.location != NSNotFound, let swiftRange = Range(range, in: value) else { return "" }
            return String(value[swiftRange])
        }
    }
}

private struct KDNAJSONSchemaEvaluator {
    let documents: [String: Any]

    func validate(
        _ instance: Any,
        schema: Any,
        document: String,
        path: String
    ) -> [String] {
        guard let schema = schema as? [String: Any] else {
            return ["\(path): schema node is not an object"]
        }
        var issues: [String] = []

        if let reference = schema["$ref"] as? String {
            guard let resolved = resolve(reference, from: document) else {
                issues.append("\(path): unresolved schema reference \(reference)")
                return issues
            }
            issues += validate(instance, schema: resolved.schema, document: resolved.document, path: path)
        }

        if let branches = schema["oneOf"] as? [Any] {
            let matches = branches.filter {
                validate(instance, schema: $0, document: document, path: path).isEmpty
            }.count
            if matches != 1 { issues.append("\(path): must match exactly one schema in oneOf") }
        }

        if let declaration = schema["type"], !matchesType(instance, declaration: declaration) {
            issues.append("\(path): type does not match schema")
            return issues
        }
        if let constant = schema["const"], !jsonEqual(instance, constant) {
            issues.append("\(path): value does not match const")
        }
        if let values = schema["enum"] as? [Any], !values.contains(where: { jsonEqual(instance, $0) }) {
            issues.append("\(path): value is not in enum")
        }

        if let string = instance as? String {
            if let minimum = schema["minLength"] as? NSNumber, string.count < minimum.intValue {
                issues.append("\(path): string is shorter than minLength")
            }
            if let pattern = schema["pattern"] as? String, !matchesPattern(string, pattern: pattern) {
                issues.append("\(path): string does not match pattern")
            }
            if let format = schema["format"] as? String {
                let valid = format == "date-time" ? KDNAJSONFormats.isDateTime(string) :
                    format == "uri" ? KDNAJSONFormats.isURI(string) : true
                if !valid { issues.append("\(path): string does not match \(format) format") }
            }
        }

        if isNumber(instance), let minimum = schema["minimum"] as? NSNumber,
           numberValue(instance) < minimum.doubleValue {
            issues.append("\(path): number is below minimum")
        }

        if let array = instance as? [Any], let itemSchema = schema["items"] {
            for (index, item) in array.enumerated() {
                issues += validate(item, schema: itemSchema, document: document, path: "\(path)[\(index)]")
            }
        }

        if let object = instance as? [String: Any] {
            let required = schema["required"] as? [String] ?? []
            for key in required where object[key] == nil {
                issues.append("\(path): required property is missing: \(key)")
            }
            let properties = schema["properties"] as? [String: Any] ?? [:]
            for key in object.keys.sorted() {
                if let propertySchema = properties[key] {
                    issues += validate(
                        object[key] as Any,
                        schema: propertySchema,
                        document: document,
                        path: "\(path).\(key)"
                    )
                } else if let additional = schema["additionalProperties"] {
                    if let allowed = additional as? Bool, !allowed {
                        issues.append("\(path): additional property is not allowed: \(key)")
                    } else if additional is [String: Any] {
                        issues += validate(
                            object[key] as Any,
                            schema: additional,
                            document: document,
                            path: "\(path).\(key)"
                        )
                    }
                }
            }
        }
        return issues
    }

    private func resolve(_ reference: String, from currentDocument: String) -> (document: String, schema: Any)? {
        let parts = reference.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false)
        let document = parts.first.map(String.init).flatMap { $0.isEmpty ? nil : $0 } ?? currentDocument
        guard var node = documents[document] else { return nil }
        guard parts.count == 2, !parts[1].isEmpty else { return (document, node) }
        let pointer = String(parts[1])
        guard pointer.first == "/" else { return nil }
        for raw in pointer.dropFirst().split(separator: "/", omittingEmptySubsequences: false) {
            let key = raw.replacingOccurrences(of: "~1", with: "/")
                .replacingOccurrences(of: "~0", with: "~")
            guard let object = node as? [String: Any], let next = object[key] else { return nil }
            node = next
        }
        return (document, node)
    }

    private func matchesType(_ value: Any, declaration: Any) -> Bool {
        let types: [String]
        if let type = declaration as? String { types = [type] }
        else if let declared = declaration as? [String] { types = declared }
        else { return false }
        return types.contains { type in
            switch type {
            case "null": return value is NSNull
            case "boolean": return isBoolean(value)
            case "string": return value is String
            case "array": return value is [Any]
            case "object": return value is [String: Any]
            case "number": return isNumber(value)
            case "integer": return isNumber(value) && numberValue(value).rounded() == numberValue(value)
            default: return false
            }
        }
    }

    private func isBoolean(_ value: Any) -> Bool {
        guard let number = value as? NSNumber else { return value is Bool }
        return CFGetTypeID(number) == CFBooleanGetTypeID()
    }

    private func isNumber(_ value: Any) -> Bool {
        value is NSNumber && !isBoolean(value)
    }

    private func numberValue(_ value: Any) -> Double {
        (value as? NSNumber)?.doubleValue ?? .nan
    }

    private func matchesPattern(_ value: String, pattern: String) -> Bool {
        guard let expression = try? NSRegularExpression(pattern: pattern) else { return false }
        let range = NSRange(value.startIndex..<value.endIndex, in: value)
        return expression.firstMatch(in: value, range: range) != nil
    }

    private func jsonEqual(_ left: Any, _ right: Any) -> Bool {
        if left is NSNull || right is NSNull { return left is NSNull && right is NSNull }
        if isBoolean(left) || isBoolean(right) {
            return isBoolean(left) && isBoolean(right) &&
                (left as? NSNumber)?.boolValue == (right as? NSNumber)?.boolValue
        }
        if isNumber(left), isNumber(right) { return numberValue(left) == numberValue(right) }
        if let left = left as? String, let right = right as? String { return left == right }
        if let left = left as? [Any], let right = right as? [Any] {
            return left.count == right.count && zip(left, right).allSatisfy(jsonEqual)
        }
        if let left = left as? [String: Any], let right = right as? [String: Any] {
            return left.keys == right.keys && left.keys.allSatisfy { key in
                guard let lhs = left[key], let rhs = right[key] else { return false }
                return jsonEqual(lhs, rhs)
            }
        }
        return false
    }
}
