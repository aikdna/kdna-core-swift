import Foundation

// The 0.5-generation R2 registry (r2-registry.js, @aikdna/kdna-core@0.36.0):
// typed targets with authored ownership, mandatory/optional edges, separate
// reference roles, unresolved externals, and the mandatory closure. Failure
// diagnostics carry the registry's field pointer and subject verbatim.
enum R2Registry {
    static func ref(_ kind: String, _ id: String) -> J { ["kind": .string(kind), "id": .string(id)] }
    static func canonicalKey(_ value: J) -> String { String(decoding: (try? KDNAJSON.canonical(value)) ?? Data(), as: UTF8.self) }
    static func sameAsset(_ a: J, _ b: J) -> Bool {
        for key in ["asset_id", "asset_version", "judgment_version"] {
            guard case .string(let left) = a[key], case .string(let right) = b[key], KDNAKey(left) == KDNAKey(right) else { return false }
        }
        return true
    }
    static func values(_ declaration: J) -> [J] { declaration["state"].text == "provided" ? declaration["value"].list : [] }
    static func fail(_ field: String = "/payload", _ subject: String? = nil) throws -> Never {
        throw PublicFailure("READ_CORE_INVALID", field: field, subject: subject)
    }
    /// Insertion-ordered map: the JS Maps these port keep insertion order,
    /// and reference iteration order is observable in the derived IR.
    struct OrderedMap<Value> {
        private(set) var keys: [String] = []
        private var index: [String: Int] = [:]
        private(set) var values: [Value] = []
        mutating func set(_ key: String, _ value: Value) {
            if let position = index[key] { values[position] = value } else { index[key] = keys.count; keys.append(key); values.append(value) }
        }
        func get(_ key: String) -> Value? { index[key].map { values[$0] } }
        var entries: [(String, Value)] { Array(zip(keys, values)) }
    }
    struct Record {
        let target: J
        let owner: J
        var rawValue: J
        let judgment: J
        let path: String
        let activation: J
        let key: String
        /// The scoped fixed-point trap (the released code re-defines the
        /// record's `value` property with a throwing getter): set to the
        /// loaded-judgment set while deriving a scoped context, so any read
        /// of an inactive judgment's value raises MissingBodyError.
        var scopeTrap: Set<String>? = nil
        func checkedValue() throws -> J {
            if let trap = scopeTrap, judgment != .null, !trap.contains(judgment.text) {
                throw MissingBodyError(judgment: judgment.text)
            }
            return rawValue
        }
    }
    struct Unresolved {
        let source: J
        var target: J
        var mandatory: Bool
    }
    final class Registry {
        let asset: J
        let payloadAsset: J
        var ordered: [Record] = []
        var index: [String: Int] = [:]
        var edges: [String: OrderedMap<Bool>] = [:]
        // The JS map allows a null reference role; "" stands for that key here
        // (declared roles are non-empty identifiers, so it cannot collide).
        var referenceRoles: [String: OrderedMap<OrderedMap<Bool>>] = [:]
        var unresolved: [Unresolved] = []
        init(_ manifest: J, _ payload: J) {
            asset = R2Registry.ref("asset", manifest["asset_uid"].text)
            payloadAsset = payload["asset"]
        }
        func setValue(_ key: String, _ value: J) {
            guard let position = index[key] else { return }
            ordered[position].rawValue = value
        }
        func local(_ target: J) -> Bool { !target.has("asset") || target["asset"] == .null || R2Registry.sameAsset(target["asset"], payloadAsset) }
        func identity(_ target: J) -> String {
            let effective = local(target) ? R2Registry.ref(target["kind"].text, target["id"].text) : target
            return R2Registry.canonicalKey(.array([effective.has("asset") ? effective["asset"] : .null, effective["kind"], effective["id"]]))
        }
        @discardableResult
        func add(_ kind: String, _ id: String, _ value: J, _ owner: J, _ judgment: J, _ path: String, _ activation: J = nil) throws -> Record {
            let target = R2Registry.ref(kind, id), key = identity(target)
            if index[key] != nil { try R2Registry.fail(path, id) }
            let record = Record(target: target, owner: owner, rawValue: value, judgment: judgment, path: path, activation: activation, key: key)
            index[key] = ordered.count
            ordered.append(record)
            edges[key] = OrderedMap<Bool>()
            referenceRoles[key] = OrderedMap<OrderedMap<Bool>>()
            return record
        }
        func get(_ target: J, _ kinds: [String]? = nil, _ field: String = "/payload") throws -> Record? {
            guard case .object = target, case .string = target["id"], kinds.map({ $0.contains(target["kind"].text) }) ?? true else { try R2Registry.fail(field, nil) }
            if !local(target) { return nil }
            guard let position = index[identity(target)] else { try R2Registry.fail(field, target["id"].text) }
            return ordered[position]
        }
        @discardableResult
        func link(_ from: J, _ target: J, _ mandatory: Bool = true, _ kinds: [String]? = nil, _ field: String = "/payload", _ referenceRole: String? = nil) throws -> Record? {
            let record = try get(target, kinds, field), fromKey = identity(from)
            guard index[fromKey] != nil else { try R2Registry.fail(field, nil) }
            guard let record else {
                if let position = unresolved.firstIndex(where: { identity($0.source) == fromKey && identity($0.target) == identity(target) }) {
                    unresolved[position].mandatory = unresolved[position].mandatory || mandatory
                } else {
                    unresolved.append(Unresolved(source: from, target: target, mandatory: mandatory))
                }
                return nil
            }
            let targetKey = identity(target)
            edges[fromKey]!.set(targetKey, (edges[fromKey]!.get(targetKey) ?? false) || mandatory)
            var byTarget = referenceRoles[fromKey]!.get(targetKey) ?? OrderedMap<Bool>()
            let roleKey = referenceRole ?? ""
            byTarget.set(roleKey, (byTarget.get(roleKey) ?? false) || mandatory)
            referenceRoles[fromKey]!.set(targetKey, byTarget)
            return record
        }
    }
    static func createRegistry(_ manifest: J, _ payload: J) throws -> Registry {
        let registry = Registry(manifest, payload)
        let asset = registry.asset
        try registry.add("asset", manifest["asset_uid"].text, nil, asset, nil, "/manifest")
        for (kind, collection) in [("actor", "actors"), ("material", "materials"), ("reason", "reasons"), ("source", "sources"), ("source_use", "source_uses"), ("resource", "resources"), ("relationship", "relationships"), ("dependency", "dependencies"), ("contract", "contracts"), ("condition", "conditions"), ("shared_declaration", "shared_declarations"), ("example", "examples")] {
            for (position, value) in payload[collection].list.enumerated() {
                try registry.add(kind, value["id"].text, value, asset, nil, "/payload/\(collection)/\(position)")
            }
        }
        func restrictions(_ holder: J, _ owner: J, _ judgment: J, _ path: String, _ isAsset: Bool = false) throws {
            for boundary in values(holder["boundaries"]) {
                try registry.add("boundary", boundary["id"].text, boundary, owner, judgment, path + "/boundaries", ["kind": "always"])
            }
            for exception in isAsset ? payload["exceptions"].list : values(holder["exceptions"]) {
                let record = try registry.add("exception", exception["id"].text, exception, owner, judgment, path + "/exceptions")
                if exception["effect"]["kind"].text == "replace_limit" {
                    try registry.add("boundary", exception["effect"]["replacement"]["id"].text, exception["effect"]["replacement"], record.target, judgment, path + "/exceptions/replacement", ["kind": "exception", "exception_ref": record.target])
                }
            }
            for misuse in isAsset ? payload["misuse"].list : values(holder["misuse"]) {
                try registry.add("misuse", misuse["id"].text, misuse, owner, judgment, path + "/misuse")
            }
        }
        try restrictions(payload["declarations"], asset, nil, "/payload/declarations", true)
        for (position, judgment) in payload["judgments"].list.enumerated() {
            let at = "/payload/judgments/\(position)", target = ref("judgment", judgment["id"].text)
            try registry.add("judgment", judgment["id"].text, judgment, asset, judgment["id"], at)
            try registry.add("contract", judgment["result_contract"]["id"].text, judgment["result_contract"], target, judgment["id"], at + "/result_contract")
            if judgment["result"] != .null {
                try registry.add("result", judgment["id"].text, judgment["result"], target, judgment["id"], at + "/result")
            }
            for component in judgment["method"]["components"].list {
                try registry.add("component", component["id"].text, component, target, judgment["id"], at + "/method/components")
            }
            for unit in judgment["method"]["units"].list {
                try registry.add("unit", unit["id"].text, unit, target, judgment["id"], at + "/method/units")
            }
            if judgment["method"]["plan"] != .null {
                let plan = try registry.add("plan", judgment["method"]["plan"]["id"].text, judgment["method"]["plan"], target, judgment["id"], at + "/method/plan")
                for node in plan.rawValue["nodes"].list {
                    try registry.add("plan_node", node["id"].text, node, plan.target, judgment["id"], at + "/method/plan/nodes")
                }
            }
            if judgment["formation_rule"]["policy"] != .null {
                let policy = try registry.add("policy", judgment["formation_rule"]["policy"]["id"].text, judgment["formation_rule"]["policy"], target, judgment["id"], at + "/formation_rule/policy")
                for entry in policy.rawValue["entries"].list {
                    try registry.add("branch_entry", entry["id"].text, entry, policy.target, judgment["id"], policy.path + "/entries")
                }
                for candidate in policy.rawValue["candidates"].list {
                    try registry.add("candidate", candidate["id"].text, candidate, policy.target, judgment["id"], policy.path + "/candidates")
                }
            }
            try restrictions(judgment, target, judgment["id"], at)
        }
        for example in payload["examples"].list {
            for result in example["results"].list {
                try registry.add("example_result", result["id"].text, result, ref("example", example["id"].text), nil, "/payload/examples/results")
            }
        }
        for revision in manifest["history"]["entries"].list {
            try registry.add("revision", revision["id"].text, revision, asset, nil, "/manifest/history/entries")
        }
        return registry
    }
    static func qualified(_ value: J) -> J {
        if value["kind"].text == "local" { return ref("judgment", value["judgment_id"].text) }
        return ["kind": "judgment", "id": value["judgment_id"], "asset": value["asset"]]
    }
    static func closure(_ registry: Registry, _ seeds: [J]) throws -> [Record] {
        var selected = Set<String>()
        var queue = seeds.map { registry.identity($0) }
        var cursor = 0
        while cursor < queue.count {
            let current = queue[cursor]; cursor += 1
            if selected.contains(current) { continue }
            guard registry.index[current] != nil else { try fail() }
            selected.insert(current)
            for (next, mandatory) in registry.edges[current]?.entries ?? [] where mandatory { queue.append(next) }
        }
        return registry.ordered.filter { selected.contains($0.key) }
    }
}

/// The scoped fixed-point's missing-body signal (section-fixedpoint.js
/// `MissingBody`): raised when a rule reads a value whose judgment body has
/// not been loaded yet; the fixed-point loop loads it and retries.
struct MissingBodyError: Error {
    let judgment: String
}
