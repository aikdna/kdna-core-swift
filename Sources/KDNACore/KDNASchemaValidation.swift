import Foundation
import CryptoKit
import CoreFoundation

/// JSON Schema resources used by the Swift loader are byte-for-byte copies of
/// the canonical schemas at
/// `aikdna/kdna@5f7ccad07758b7766237590e5b9ba47301036f6b`. Validation fails
/// closed if a bundled resource is missing or its digest changes without
/// updating this lock. The evaluator
/// intentionally implements the complete set of JSON Schema keywords used by
/// the pinned authoring and Runtime-contract schemas, including local/external
/// refs.
enum KDNACanonicalSchemas {
    static let canonicalCommit = "5f7ccad07758b7766237590e5b9ba47301036f6b"

    static let expectedDigests = [
        "agent-host-capabilities.schema.json": "00ab3aeceffae5061faeecfdb82ac95afde4c60ad73faa796b2d7bd463e2e834",
        "agent-host-receipt.schema.json": "ecdac9d9b6670ead0cf94b3c307b7d9580e4eacdf0d1ce683d2b100b59a3f115",
        "agent-host-request.schema.json": "e827bc2ca51937c31d9ff089b9ae9b37f154ae69836d778f0027480f0d2ee693",
        "bundle-profile.schema.json": "45370bc73504df26a25d2e391cf543a468f872be835e57ac17ebc5c95d13f3ef",
        "checksums.schema.json": "7fd1f5d5a98a2f0a4d311a6ebba7d13d0e00253ab042098ac0aeec9e31c4d4e8",
        "consumption-plan.schema.json": "f73c52884c59e1566d4e6121e42b9e2dfed43ffbee6452b6239a56cf8262785f",
        "digest-evidence.schema.json": "294939c0a230639a1ae7b059a28d87310ead350ff03d9d6cf46e112acf3d9f75",
        "external-grant-envelope.schema.json": "245697c461cecf4fd68877d50d4489127f0375f99fda6f5ead41971d8776f6ca",
        "external-key-grant.schema.json": "d0281a11ba405360bc45bd4894dcdfbed3a85664566af987b7147d5622ffb749",
        "judgment-trace.schema.json": "a260e5abbcc68bf8df11ba738b5d475901b2950668c4718e415355adc723c7b0",
        "load-contract.schema.json": "1b262a02f3c63ec25c72ae6dc79c4a472325414d4b06c6fa3f85f56998178ebb",
        "load-plan.schema.json": "18915f1d0fd6dc2b79e60f67e836359897beed8406625c7485c75aa2cd2b3e5a",
        "manifest.schema.json": "73a1c89fa617f0d13d17d69ad7a7070553a8fc74da2751819d640f6b8c0e92b6",
        "payload-profile.schema.json": "c65afb38b47c115680d121838ec3640266455d5b2d472b3e0e8904f60d734012",
        "runtime-capsule.schema.json": "344e584a8b264ce381c2b754e69d46664d6dba049e6a2ffae8731df9ec05e6f6",
    ]

    static func validateManifest(_ instance: Any) -> [String] {
        validate(instance, against: "manifest.schema.json")
    }

    static func validatePayload(_ instance: Any) -> [String] {
        var issues = validate(instance, against: "payload-profile.schema.json")

        // `reasoning.self_check` is the sole canonical source field. Preserve
        // one stable, actionable diagnostic for the removed plural alias
        // after the canonical false schema has rejected it.
        if let payload = instance as? [String: Any],
           let reasoning = payload["reasoning"] as? [String: Any],
           reasoning.keys.contains("self_checks") {
            issues.removeAll { $0.hasPrefix("$.reasoning.self_checks:") }
            issues.append(
                "$.reasoning.self_checks: deprecated alias is not allowed; use $.reasoning.self_check"
            )
        }

        return issues
    }

    static func validateLoadContract(_ instance: Any) -> [String] {
        validate(instance, against: "load-contract.schema.json")
    }

    static func validateLoadPlan(_ instance: Any) -> [String] {
        validate(instance, against: "load-plan.schema.json")
    }

    static func validateBundleProfile(_ instance: Any) -> [String] {
        validate(instance, against: "bundle-profile.schema.json")
    }

    static func validateExternalGrantEnvelope(_ instance: Any) -> [String] {
        validate(instance, against: "external-grant-envelope.schema.json")
    }

    static func validateExternalKeyGrant(_ instance: Any) -> [String] {
        validate(instance, against: "external-key-grant.schema.json")
    }

    static func validateChecksums(_ instance: Any) -> [String] {
        validate(instance, against: "checksums.schema.json")
    }

    static func validateRuntimeCapsule(_ instance: Any) -> [String] {
        validate(instance, against: "runtime-capsule.schema.json")
    }

    static func validateConsumptionPlan(_ instance: Any) -> [String] {
        validate(instance, against: "consumption-plan.schema.json")
    }

    static func validateAgentHostCapabilities(_ instance: Any) -> [String] {
        validate(instance, against: "agent-host-capabilities.schema.json")
    }

    static func validateAgentHostRequest(_ instance: Any) -> [String] {
        validate(instance, against: "agent-host-request.schema.json")
    }

    static func validateAgentHostReceipt(_ instance: Any) -> [String] {
        validate(instance, against: "agent-host-receipt.schema.json")
    }

    static func validateJudgmentTrace(_ instance: Any) -> [String] {
        validate(instance, against: "judgment-trace.schema.json")
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
                let document = try JSONSerialization.jsonObject(
                    with: resourceData(named: resourceName)
                )
                documents[resourceName] = document
                if let identifier = (document as? [String: Any])?["$id"] as? String {
                    documents[identifier] = document
                }
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
        if let allowed = schema as? Bool {
            return allowed ? [] : ["\(path): value is disallowed by schema"]
        }
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
        if let branches = schema["anyOf"] as? [Any], !branches.contains(where: {
            validate(instance, schema: $0, document: document, path: path).isEmpty
        }) {
            issues.append("\(path): must match at least one schema in anyOf")
        }
        if let branches = schema["allOf"] as? [Any] {
            for branch in branches {
                issues += validate(instance, schema: branch, document: document, path: path)
            }
        }
        if let condition = schema["if"] {
            let matched = validate(instance, schema: condition, document: document, path: path).isEmpty
            if matched, let consequence = schema["then"] {
                issues += validate(instance, schema: consequence, document: document, path: path)
            } else if !matched, let alternative = schema["else"] {
                issues += validate(instance, schema: alternative, document: document, path: path)
            }
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
            if let maximum = schema["maxLength"] as? NSNumber, string.count > maximum.intValue {
                issues.append("\(path): string is longer than maxLength")
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

        if let array = instance as? [Any] {
            if let minimum = schema["minItems"] as? NSNumber, array.count < minimum.intValue {
                issues.append("\(path): array has fewer items than minItems")
            }
            if let maximum = schema["maxItems"] as? NSNumber, array.count > maximum.intValue {
                issues.append("\(path): array has more items than maxItems")
            }
            if (schema["uniqueItems"] as? Bool) == true {
                for left in array.indices {
                    if array.indices.contains(where: { $0 > left && jsonEqual(array[left], array[$0]) }) {
                        issues.append("\(path): array items are not unique")
                        break
                    }
                }
            }
            let prefixSchemas = schema["prefixItems"] as? [Any] ?? []
            for (index, itemSchema) in prefixSchemas.enumerated() where index < array.count {
                issues += validate(
                    array[index],
                    schema: itemSchema,
                    document: document,
                    path: "\(path)[\(index)]"
                )
            }
            if let itemSchema = schema["items"] {
                for index in prefixSchemas.count..<array.count {
                    let item = array[index]
                issues += validate(item, schema: itemSchema, document: document, path: "\(path)[\(index)]")
                }
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
