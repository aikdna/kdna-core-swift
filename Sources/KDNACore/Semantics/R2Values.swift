import Foundation

// The 0.5-generation R2 value shapes (r2-values.js,
// @aikdna/kdna-core@0.36.0): contracts, scalar/list/record shapes, result
// values, projections, contract compatibility and binding completeness.
// Failures carry the field pointer verbatim (READ_CORE_INVALID).
//
// One named deviation: JS Map keys for `unique` use value identity, which
// for the string keys the contract actually uses equals canonical-key
// equality; the canonical key is used uniformly here (object keys are
// schema-invalid at these call sites).
enum R2Values {
    static func equal(_ a: J, _ b: J) -> Bool {
        guard let left = try? KDNAJSON.canonical(a), let right = try? KDNAJSON.canonical(b) else { return false }
        return left == right
    }
    static func fail(_ field: String = "/payload", _ subject: String? = nil) throws -> Never {
        throw PublicFailure("READ_CORE_INVALID", field: field, subject: subject)
    }
    static func unique(_ items: [J], _ name: String = "id", _ field: String = "/payload") throws -> [String: J] {
        var result: [String: J] = [:]
        for item in items {
            let key = R2Registry.canonicalKey(item[name])
            if result[key] != nil { try fail(field, item[name].text) }
            result[key] = item
        }
        return result
    }
    static func bounds(_ value: J, _ field: String = "/payload") throws {
        let minimum = value["minimum"], maximum = value["maximum"]
        // JS compares `value.maximum === null`: an absent maximum is not an
        // explicit null and fails here.
        let maximumValid = value.has("maximum") && (maximum == .null || (isUInt(maximum) && maximum.numeric >= minimum.numeric))
        guard isUInt(minimum), maximumValid else { try fail(field, nil) }
    }
    static func validateShape(_ shape: J, _ field: String = "/payload", _ depth: Int = 0) throws {
        if depth > 64 { try fail(field, nil) }
        switch shape["kind"].text {
        case "list":
            try bounds(shape, field)
            try validateShape(shape["item_shape"], field, depth + 1)
        case "record":
            _ = try unique(shape["fields"].list, "name", field)
            for fieldShape in shape["fields"].list { try validateShape(fieldShape["shape"], field, depth + 1) }
        case "scalar": break
        default: try fail(field, nil)
        }
    }
    static func resultShape(_ shape: J, _ value: J, _ field: String = "/payload", _ depth: Int = 0) throws {
        if depth > 64 { try fail(field, nil) }
        switch shape["kind"].text {
        case "scalar":
            if value["kind"].text != shape["scalar_type"].text { try fail(field, nil) }
        case "list":
            if value["kind"].text != "list" || Double(value["items"].list.count) < shape["minimum"].numeric
                || (shape["maximum"] != .null && Double(value["items"].list.count) > shape["maximum"].numeric) { try fail(field, nil) }
            for item in value["items"].list { try resultShape(shape["item_shape"], item, field, depth + 1) }
        default:
            if value["kind"].text != "record" { try fail(field, nil) }
            let fields = try unique(shape["fields"].list, "name", field), actual = try unique(value["fields"].list, "name", field)
            for fieldShape in fields.values where fieldShape["required"] == .bool(true) && actual[R2Registry.canonicalKey(fieldShape["name"])] == nil { try fail(field, nil) }
            for actualField in actual.values {
                let key = R2Registry.canonicalKey(actualField["name"])
                guard let fieldShape = fields[key] else { try fail(field, nil) }
                try resultShape(fieldShape["shape"], actualField["value"], field, depth + 1)
            }
        }
    }
    static func validateContract(_ contract: J, _ field: String = "/payload") throws {
        if contract["kind"].text == "emission_list" { return }
        try bounds(contract, field)
        try validateShape(contract["shape"], field)
        let types = contract["allowed_result_types"].list
        if types.isEmpty || Set(types.map { R2Registry.canonicalKey($0) }).count != types.count { try fail(field, nil) }
    }
    static func valueFor(_ contract: J, _ value: J, _ field: String = "/payload") throws {
        if contract["kind"].text == "emission_list" { try fail(field, nil) }
        try resultShape(contract["shape"], value, field)
        let count = value["kind"].text == "list" ? value["items"].list.count : 1
        if Double(count) < contract["minimum"].numeric || (contract["maximum"] != .null && Double(count) > contract["maximum"].numeric) { try fail(field, nil) }
    }
    static func validateResult(_ judgment: J) throws {
        let contract = judgment["result_contract"]
        try validateContract(contract)
        if judgment["result"] != .null {
            let matching = contract["allowed_result_types"].list.contains { equal($0, judgment["result"]["result_type"]) }
            if !exact(judgment["result"]["contract_ref"].text, contract["id"].text) || !matching { try fail() }
            try valueFor(contract, judgment["result"]["value"])
        }
        if judgment["formation_rule"] != .null && !exact(judgment["formation_rule"]["output_contract_ref"].text, contract["id"].text) { try fail() }
    }
    static func shapeAt(_ shape: J, _ path: [String], _ field: String = "/payload") throws -> J {
        var current = shape
        for name in path {
            guard current["kind"].text == "record" else { try fail(field, nil) }
            guard let fieldShape = current["fields"].list.first(where: { exact($0["name"].text, name) }) else { try fail(field, nil) }
            current = fieldShape["shape"]
        }
        return current
    }
    static func compatible(_ from: J, _ to: J, _ field: String = "/payload") throws {
        if from == .null || to == .null { return }
        if from["kind"].text == "emission_list" || to["kind"].text == "emission_list" {
            if !equal(from, to) { try fail(field, nil) }
            return
        }
        if !equal(from["shape"], to["shape"]) || from["minimum"].numeric < to["minimum"].numeric || (to["maximum"] != .null && (from["maximum"] == .null || from["maximum"].numeric > to["maximum"].numeric)) { try fail(field, nil) }
        if from.has("allowed_result_types") && to.has("allowed_result_types") {
            let subset = from["allowed_result_types"].list.allSatisfy { candidate in to["allowed_result_types"].list.contains { equal(candidate, $0) } }
            if !subset { try fail(field, nil) }
        }
    }
    static func projected(_ contract: J, _ path: [String], _ field: String = "/payload") throws -> J? {
        if path.isEmpty { return contract }
        if contract == .null { return nil }
        if contract["kind"].text == "emission_list" { try fail(field, nil) }
        let shape = try shapeAt(contract["shape"], path, field)
        if shape["kind"].text == "list" { return ["shape": shape, "minimum": shape["minimum"], "maximum": shape["maximum"]] }
        return ["shape": shape, "minimum": 1, "maximum": 1]
    }
    static func completeBindings(_ shape: J, _ paths: [[String]], _ field: String = "/payload") throws {
        func prefix(_ a: [String], _ b: [String]) -> Bool { a.count <= b.count && zip(a, b).allSatisfy { exact($0, $1) } }
        for i in paths.indices { for j in paths.indices where j > i { if prefix(paths[i], paths[j]) || prefix(paths[j], paths[i]) { try fail(field, nil) } } }
        if paths.contains(where: { $0.isEmpty }) {
            if paths.count != 1 { try fail(field, nil) }
            return
        }
        func required(_ value: J, _ at: [String]) throws {
            if paths.contains(where: { prefix($0, at) }) { return }
            if value["kind"].text != "record" { try fail(field, nil) }
            for fieldValue in value["fields"].list where fieldValue["required"] == .bool(true) {
                try required(fieldValue["shape"], at + [fieldValue["name"].text])
            }
        }
        try required(shape, [])
    }
}
