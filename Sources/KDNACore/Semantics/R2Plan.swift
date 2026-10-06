import Foundation

// The 0.5-generation plan semantics (r2-plan.js, @aikdna/kdna-core@0.36.0):
// validation of the finite authored plan description — node graph shape,
// ports and endpoints, input supplies, feedback rounds and updates, links,
// result bindings, method contribution and the formation-policy coupling.
// It never evaluates a condition, invokes a method, or performs a round.
//
// The helpers are context methods (the released code carries them in the
// per-judgment context closure, and the formation-policy section uses them
// across judgments). Whole-read path only (scope == null); the scope
// branches belong to the partial-read flows (Stage B).
enum R2Plan {
    struct Supply {
        let path: [String]
        let source: J
    }
    struct Endpoint {
        let node: J
        let contract: J
        let whole: J?
        let path: [String]
        let port: String
    }
    final class Context {
        let r: R2Registry.Registry
        let judgment: J
        let plan: J
        let at: String
        let nodes: R2Registry.OrderedMap<J>
        let units: [String: J]
        let normalContract: (J, String) throws -> J
        var parents: [String: String] = [:]
        var children: [String: [String]] = [:]
        var graph: [String: Set<String>] = [:]
        var inputSupplies: [String: [Supply]] = [:]
        var instanceMethods: [String: Set<String>] = [:]
        var portCache: [String: J] = [:]
        var resolving = Set<String>()
        var contributing = Set<String>()
        var methods = Set<String>()
        init(r: R2Registry.Registry, judgment: J, plan: J, at: String, nodes: R2Registry.OrderedMap<J>, units: [String: J], normalContract: @escaping (J, String) throws -> J) {
            self.r = r; self.judgment = judgment; self.plan = plan; self.at = at; self.nodes = nodes; self.units = units; self.normalContract = normalContract
        }
        func localNode(_ target: J) throws -> J {
            guard let record = try r.get(target, ["plan_node"], at), record.owner["kind"].text == "plan", record.owner["id"].text == plan["id"].text, nodes.get(R2Registry.canonicalKey(record.target["id"])) != nil else {
                try R2Registry.fail(at)
            }
            return record.value
        }
        func child(_ parent: J, _ target: J) throws {
            let value = try localNode(target)
            if parents[value["id"].text] != nil { try R2Registry.fail(at) }
            parents[value["id"].text] = parent["id"].text
            children[parent["id"].text]!.append(value["id"].text)
            _ = try r.link(R2Registry.ref("plan_node", parent["id"].text), target, true, ["plan_node"], at, nil)
        }
        func ancestors(_ start: String) -> [String] {
            var out: [String] = [], id = start
            while let parent = parents[id] { out.append(parent); id = parent }
            return out
        }
        func within(_ id: String, _ parent: String) -> Bool { id == parent || ancestors(id).contains(parent) }
        func round(_ id: String) -> String { ancestors(id).filter { nodes.get(R2Registry.canonicalKey(.string($0)))?["kind"].text == "feedback" }.joined(separator: "\0") }
        func ordered(_ from: String, _ to: String) throws {
            let a = [from] + ancestors(from), b = [to] + ancestors(to)
            guard let common = a.first(where: { b.contains($0) }), common != from, common != to else { return }
            let type = nodes.get(R2Registry.canonicalKey(.string(common)))!["kind"].text
            let left = a[a.firstIndex(of: common)! - 1], right = b[b.firstIndex(of: common)! - 1]
            if left == right { return }
            if type == "parallel" || (type == "sequence" && children[common]!.firstIndex(of: left)! >= children[common]!.firstIndex(of: right)!) { try R2Registry.fail(at) }
        }
        func dataEdge(_ from: String, _ to: String, _ checkOrder: Bool = true) throws {
            if from == to { try R2Registry.fail(at) }
            if checkOrder { try ordered(from, to) }
            graph[from]!.insert(to)
        }
        func contractValue(_ target: J, _ allowSpecial: Bool = false) throws -> J {
            guard let record = try r.get(target, ["contract"], at) else { return .null }
            if !allowSpecial && record.value["kind"].text == "emission_list" { try R2Registry.fail(at) }
            return record.value
        }
        func ports(_ node: J) throws -> (inputs: J, outputs: J) {
            if let cached = portCache[node["id"].text] { return (cached["inputs"], cached["outputs"]) }
            if resolving.contains(node["id"].text) { try R2Registry.fail(at) }
            resolving.insert(node["id"].text)
            defer { resolving.remove(node["id"].text) }
            var result: (inputs: J, outputs: J)
            if node["kind"].text == "use" {
                guard let unitRecord = try r.get(node["unit_ref"], ["unit"], at), unitRecord.judgment.text == judgment["id"].text, let unit = units[node["unit_ref"]["id"].text] else {
                    try R2Registry.fail(at)
                }
                _ = try r.link(R2Registry.ref("plan_node", node["id"].text), unitRecord.target, true, ["unit"], at, nil)
                instanceMethods[node["id"].text] = [unit["method"].text]
                result = (unit["inputs"], unit["outputs"])
            } else if node["kind"].text == "judgment_use" {
                let target = R2Registry.qualified(node["judgment_ref"])
                if let record = try r.link(R2Registry.ref("plan_node", node["id"].text), target, true, ["judgment"], at, nil) {
                    callTargets[judgment["id"].text]!.insert(record.target["id"].text)
                    result = (.array(record.value["ports"].list.filter { $0["direction"].text == "input" }),
                              .array(record.value["ports"].list.filter { $0["direction"].text == "output" }))
                    instanceMethods[node["id"].text] = [record.value["method"]["method"]["term"].text]
                } else {
                    result = (.null, .null)
                }
            } else if node["kind"].text == "branch" {
                let policy = try r.get(node["policy_ref"], ["policy"], at)
                result = (.array([]), .array([["name": "result", "contract_ref": policy?.value["result_contract_ref"] ?? .null]]))
            } else if node["kind"].text == "feedback" {
                let output = try endpoint(node["output"], "output", false)
                result = (.array([]), .array([["name": "result", "resolved_contract": output.contract]]))
            } else {
                result = (.array([]), .array([]))
            }
            portCache[node["id"].text] = ["inputs": result.inputs, "outputs": result.outputs]
            return result
        }
        var callTargets: [String: Set<String>] = [:]
        func endpoint(_ value: J, _ direction: String, _ allowSpecial: Bool = false) throws -> Endpoint {
            let node = try localNode(value["node_ref"])
            let portsValue = try ports(node)
            let list = direction == "input" ? portsValue.inputs : portsValue.outputs
            let path = value["field_path"].list.map { $0.text }
            if case .null = list { return Endpoint(node: node, contract: .null, whole: nil, path: path, port: value["port"].text) }
            guard let port = list.list.first(where: { $0["name"].text == value["port"].text }) else { try R2Registry.fail(at) }
            let whole = port.has("resolved_contract") ? port["resolved_contract"] : (try contractValue(port["contract_ref"], allowSpecial))
            return Endpoint(node: node, contract: try R2Values.projected(whole, path, at) ?? .null, whole: whole, path: path, port: value["port"].text)
        }
        func supply(_ node: String, _ port: String, _ path: [String], _ source: J) {
            let id = R2Registry.canonicalKey(.array([.string(node), .string(port)]))
            inputSupplies[id, default: []].append(Supply(path: path, source: source))
        }
    }
    static func producerKey(_ registry: R2Registry.Registry, _ producer: J) -> String {
        producer["kind"] != .null
            ? registry.identity(producer)
            : R2Registry.canonicalKey(.array([.string(registry.identity(producer["node_ref"])), producer["port"], producer["field_path"]]))
    }
    static func acyclic(_ graph: [String: Set<String>], _ at: String) throws {
        var done = Set<String>(), active = Set<String>()
        func visit(_ id: String) throws {
            if done.contains(id) { return }
            if active.contains(id) { try R2Registry.fail(at) }
            active.insert(id)
            for next in graph[id] ?? [] { try visit(next) }
            active.remove(id); done.insert(id)
        }
        for id in graph.keys { try visit(id) }
    }
    static func checkPlans(_ payload: J, _ r: R2Registry.Registry, _ normalContract: @escaping (J, String) throws -> J) throws {
        var contexts: R2Registry.OrderedMap<Context> = R2Registry.OrderedMap<Context>()
        for judgment in payload["judgments"].list {
            let plan = judgment["method"]["plan"]
            if plan == .null { continue }
            let position = payload["judgments"].list.firstIndex(where: { $0 == judgment })!
            let at = "/payload/judgments/\(position)/method/plan"
            let nodes = try R2Values.unique(plan["nodes"].list, "id", at)
            var units: [String: J] = [:]
            for unit in judgment["method"]["units"].list { units[unit["id"].text] = unit }
            let context = Context(r: r, judgment: judgment, plan: plan, at: at, nodes: nodes, units: units, normalContract: normalContract)
            var childrenInit: [String: [String]] = [:]
            for node in plan["nodes"].list { childrenInit[node["id"].text] = []; context.graph[node["id"].text] = [] }
            context.children = childrenInit
            for node in plan["nodes"].list {
                _ = try r.link(R2Registry.ref("plan", plan["id"].text), R2Registry.ref("plan_node", node["id"].text), true, ["plan_node"], at, nil)
            }
            for node in plan["nodes"].list {
                if ["sequence", "parallel"].contains(node["kind"].text) {
                    if node["children"].list.count < (node["kind"].text == "parallel" ? 2 : 1) { try R2Registry.fail(at) }
                    for target in node["children"].list { try context.child(node, target) }
                } else if node["kind"].text == "feedback" {
                    try context.child(node, node["body"])
                } else if node["kind"].text == "branch" {
                    let policy = try r.get(node["policy_ref"], ["policy"], at)
                    if policy == nil || policy!.judgment.text != judgment["id"].text { try R2Registry.fail(at) }
                    _ = try r.link(R2Registry.ref("plan_node", node["id"].text), policy!.target, true, ["policy"], at, nil)
                    if policy!.value["combine"]["kind"].text == "authored" {
                        try context.child(node, policy!.value["combine"]["merge_node_ref"])
                    }
                }
            }
            let root = try context.localNode(plan["root"])
            if context.parents[root["id"].text] != nil
                || plan["nodes"].list.contains(where: { $0["id"].text != root["id"].text && context.parents[$0["id"].text] == nil }) { try R2Registry.fail(at) }
            try acyclic(context.children.mapValues { Set($0) }, at)
            var reached = Set<String>()
            func reach(_ id: String) { if reached.contains(id) { return }; reached.insert(id); for next in context.children[id] ?? [] { reach(next) } }
            reach(root["id"].text)
            if reached.count != nodes.keys.count { try R2Registry.fail(at) }
            for node in plan["nodes"].list {
                let ps = try context.ports(node)
                if !["use", "judgment_use"].contains(node["kind"].text) { continue }
                let bindingPorts = node["input_bindings"].list.map { $0["port"].text }
                if Set(bindingPorts).count != bindingPorts.count { try R2Registry.fail(at) }
                for binding in node["input_bindings"].list {
                    let target = try context.endpoint(["node_ref": R2Registry.ref("plan_node", node["id"].text), "port": binding["port"], "field_path": .array([])], "input")
                    if binding["from"]["kind"].text == "literal" {
                        if target.contract != .null { try R2Values.valueFor(target.contract, binding["from"]["value"], at) }
                    } else if binding["from"]["kind"].text == "input" {
                        guard let input = judgment["inputs"].list.first(where: { $0["name"].text == binding["from"]["name"].text }) else { try R2Registry.fail(at) }
                        try R2Values.compatible(try normalContract(input["contract_ref"], at), target.contract, at)
                    } else {
                        let feedback = try context.localNode(binding["from"]["feedback_ref"])
                        if feedback["kind"].text != "feedback" || !context.within(node["id"].text, feedback["body"]["id"].text) { try R2Registry.fail(at) }
                        guard let state = feedback["state"].list.first(where: { $0["name"].text == binding["from"]["slot"].text }) else { try R2Registry.fail(at) }
                        try R2Values.compatible(try normalContract(state["contract_ref"], at), target.contract, at)
                        let updates = feedback["updates"].list.filter { update in
                            update["state_slot"].text == state["name"].text && update["next_input"]["node_ref"]["id"].text == node["id"].text
                                && update["next_input"]["port"].text == binding["port"].text && update["next_input"]["field_path"].list.isEmpty
                        }
                        if updates.count != 1 { try R2Registry.fail(at) }
                    }
                    context.supply(node["id"].text, binding["port"].text, [], binding["from"])
                }
                if case .array = ps.inputs { _ = try R2Values.unique(ps.inputs.list, "name", at) }
            }
            for flow in plan["links"].list {
                let from = try context.endpoint(flow["from"], "output"), to = try context.endpoint(flow["to"], "input")
                if context.round(from.node["id"].text) != context.round(to.node["id"].text) { try R2Registry.fail(at) }
                try R2Values.compatible(from.contract, to.contract, at)
                try context.dataEdge(from.node["id"].text, to.node["id"].text)
                context.supply(to.node["id"].text, to.port, to.path, ["kind": "link", "from": flow["from"]])
                _ = try r.link(R2Registry.ref("plan_node", to.node["id"].text), R2Registry.ref("plan_node", from.node["id"].text), true, ["plan_node"], at, nil)
            }
            for node in plan["nodes"].list where node["kind"].text == "feedback" {
                _ = try R2Values.unique(node["state"].list, "name", at)
                _ = try R2Values.unique(node["updates"].list, "state_slot", at)
                if node["state"].list.isEmpty || node["state"].list.count != node["updates"].list.count { try R2Registry.fail(at) }
                if node["termination"]["kind"].text == "condition" {
                    _ = try r.link(R2Registry.ref("plan_node", node["id"].text), node["termination"]["when"], true, ["condition"], at, nil)
                }
                let output = try context.endpoint(node["output"], "output", false)
                if !context.within(output.node["id"].text, node["body"]["id"].text) { try R2Registry.fail(at) }
                context.graph[output.node["id"].text]!.insert(node["id"].text)
                for state in node["state"].list {
                    let c = try normalContract(state["contract_ref"], at)
                    if c != .null { try R2Values.valueFor(c, state["initial"], at) }
                    _ = try r.link(R2Registry.ref("plan_node", node["id"].text), state["contract_ref"], true, ["contract"], at, nil)
                }
                for update in node["updates"].list {
                    guard let state = node["state"].list.first(where: { $0["name"].text == update["state_slot"].text }) else { try R2Registry.fail(at) }
                    let from = try context.endpoint(update["from"], "output"), to = try context.endpoint(update["next_input"], "input")
                    if !context.within(from.node["id"].text, node["body"]["id"].text) || !context.within(to.node["id"].text, node["body"]["id"].text) { try R2Registry.fail(at) }
                    let c = try normalContract(state["contract_ref"], at)
                    try R2Values.compatible(from.contract, c, at)
                    try R2Values.compatible(c, to.contract, at)
                    let key = R2Registry.canonicalKey(.array([.string(to.node["id"].text), .string(to.port)]))
                    let existing = context.inputSupplies[key] ?? []
                    let initializer = existing.filter { supply in
                        supply.source["kind"].text == "state" && supply.source["feedback_ref"]["id"].text == node["id"].text
                            && supply.source["slot"].text == state["name"].text && supply.path == to.path
                    }
                    if initializer.count > 1 || (existing.contains { $0.source["kind"].text == "state" } && initializer.count != 1) { try R2Registry.fail(at) }
                    if initializer.isEmpty {
                        context.supply(to.node["id"].text, to.port, to.path, ["kind": "feedback", "feedback_ref": R2Registry.ref("plan_node", node["id"].text), "slot": state["name"]])
                    }
                    // The update is an edge between rounds, deliberately absent from graph.
                }
            }
            contexts.set(judgment["id"].text, context)
        }
        for judgment in payload["judgments"].list {
            let policy = judgment["formation_rule"]["policy"]
            if policy == .null { continue }
            let context = contexts.get(judgment["id"].text)
            let position = payload["judgments"].list.firstIndex(where: { $0 == judgment })!
            let at = "/payload/judgments/\(position)/formation_rule/policy"
            let ptarget = R2Registry.ref("policy", policy["id"].text), output = try normalContract(policy["result_contract_ref"], at)
            _ = try r.link(ptarget, policy["result_contract_ref"], true, ["contract"], at, nil)
            try R2Values.compatible(output, judgment["result_contract"], at)
            let candidates = try R2Values.unique(policy["candidates"].list, "id", at)
            var producers = R2Registry.OrderedMap<J>()
            for candidate in policy["candidates"].list {
                _ = try r.link(R2Registry.ref("candidate", candidate["id"].text), candidate["contract_ref"], true, ["contract"], at, nil)
                let c = try normalContract(candidate["contract_ref"], at)
                if c != .null { try R2Values.valueFor(c, candidate["value"], at) }
            }
            var branchNodes: [J] = []
            if let context {
                branchNodes = context.nodes.values.filter { $0["kind"].text == "branch" && $0["policy_ref"]["id"].text == policy["id"].text }
            }
            for entry in policy["entries"].list {
                let etarget = R2Registry.ref("branch_entry", entry["id"].text)
                _ = try r.link(ptarget, etarget, true, ["branch_entry"], at, nil)
                _ = try r.link(etarget, entry["when"], true, ["condition"], at, nil)
                let c: J
                let producer: J
                if entry["then"]["kind"].text == "candidate" {
                    guard let candidate = try r.get(entry["then"]["candidate_ref"], ["candidate"], at), candidate.owner["id"].text == policy["id"].text,
                          candidates.get(R2Registry.canonicalKey(candidate.target["id"])) != nil else { try R2Registry.fail(at) }
                    _ = try r.link(etarget, candidate.target, true, ["candidate"], at, nil)
                    c = try normalContract(candidate.value["contract_ref"], at)
                    producer = candidate.target
                } else {
                    guard let context else { try R2Registry.fail(at) }
                    let from = try context.endpoint(entry["then"]["from"], "output")
                    c = try normalContract(entry["then"]["contract_ref"], at)
                    try R2Values.compatible(from.contract, c, at)
                    producer = entry["then"]["from"]
                    if branchNodes.contains(where: { $0["id"].text == from.node["id"].text })
                        || (policy["combine"]["kind"].text == "authored" && policy["combine"]["merge_node_ref"]["id"].text == from.node["id"].text) { try R2Registry.fail(at) }
                    for branch in branchNodes {
                        if context.round(from.node["id"].text) != context.round(branch["id"].text) { try R2Registry.fail(at) }
                        try context.dataEdge(from.node["id"].text, branch["id"].text)
                    }
                    _ = try r.link(etarget, R2Registry.ref("plan_node", from.node["id"].text), true, ["plan_node"], at, nil)
                    _ = try r.link(etarget, entry["then"]["contract_ref"], true, ["contract"], at, nil)
                }
                producers.set(producerKey(r, producer), c)
            }
            if policy["match"].text == "first_match" {
                if policy["combine"] != .null || policy["on_undetermined"]["kind"].text != "defer" { try R2Registry.fail(at) }
                for c in producers.values { try R2Values.compatible(c, output, at) }
            } else if policy["combine"] == .null {
                try R2Registry.fail(at)
            }
            if policy["match"].text == "first_match" || policy["combine"]["order"].text == "priority" {
                let priorities = policy["entries"].list.map { $0["priority"] }
                if priorities.contains(where: { !isUInt($0) }) || Set(priorities.map { R2Registry.canonicalKey($0) }).count != priorities.count { try R2Registry.fail(at) }
            }
            for set in policy["exclusive_sets"].list {
                let keys = set.list.map { producerKey(r, $0) }
                if keys.count < 2 || Set(keys).count != keys.count || keys.contains(where: { producers.get($0) == nil }) { try R2Registry.fail(at) }
            }
            if policy["on_no_match"]["kind"].text == "value" {
                let c = try normalContract(policy["on_no_match"]["contract_ref"], at)
                try R2Values.compatible(c, output, at)
                if c != .null { try R2Values.valueFor(c, policy["on_no_match"]["value"], at) }
                _ = try r.link(ptarget, policy["on_no_match"]["contract_ref"], true, ["contract"], at, nil)
            }
            if policy["combine"]["kind"].text == "collect" {
                let item = try normalContract(policy["combine"]["item_contract_ref"], at)
                _ = try r.link(ptarget, policy["combine"]["item_contract_ref"], true, ["contract"], at, nil)
                if output != .null && item != .null {
                    let ok = output["shape"]["kind"].text == "list" && R2Values.equal(output["shape"]["item_shape"], item["shape"])
                        && R2Values.equal(output["minimum"], output["shape"]["minimum"]) && R2Values.equal(output["maximum"], output["shape"]["maximum"])
                        && output["minimum"].numeric == 0 && (output["maximum"] == .null || output["maximum"].numeric >= Double(policy["entries"].list.count))
                    if !ok { try R2Registry.fail(at) }
                }
                for c in producers.values { try R2Values.compatible(c, item, at) }
                if policy["on_undetermined"]["kind"].text == "partial" && !policy["exclusive_sets"].list.isEmpty { try R2Registry.fail(at) }
            } else if policy["combine"]["kind"].text == "authored" {
                guard let context, branchNodes.count == 1, policy["on_undetermined"]["kind"].text == "defer" else { try R2Registry.fail(at) }
                let combine = policy["combine"]
                guard let merge = context.nodes.get(R2Registry.canonicalKey(combine["merge_node_ref"]["id"])), merge["kind"].text == "use",
                      context.parents[merge["id"].text] == branchNodes[0]["id"].text else { try R2Registry.fail(at) }
                let input = try context.endpoint(["node_ref": combine["merge_node_ref"], "port": combine["input_port"], "field_path": .array([])], "input", true)
                let merged = try context.endpoint(["node_ref": combine["merge_node_ref"], "port": combine["output_port"], "field_path": .array([])], "output")
                if input.contract["kind"].text != "emission_list" || r.identity(input.contract["policy_ref"]) != r.identity(ptarget) { try R2Registry.fail(at) }
                try R2Values.compatible(merged.contract, output, at)
                context.supply(merge["id"].text, combine["input_port"].text, [], ["kind": "policy", "policy_ref": ptarget])
                context.graph[merge["id"].text]!.insert(branchNodes[0]["id"].text)
                for entry in policy["entries"].list where entry["then"]["kind"].text == "output" {
                    context.graph[entry["then"]["from"]["node_ref"]["id"].text]!.insert(merge["id"].text)
                }
            }
            if policy["on_undetermined"]["kind"].text == "partial" && !(policy["match"].text == "all_matches" && policy["combine"]["kind"].text == "collect") { try R2Registry.fail(at) }
        }
        for judgment in payload["judgments"].list {
            guard let context = contexts.get(judgment["id"].text) else { continue }
            let at = context.at
            for node in context.nodes.values where ["use", "judgment_use"].contains(node["kind"].text) {
                let nodePorts = try context.ports(node)
                if case .array(let inputList) = nodePorts.inputs {
                    for port in inputList {
                        let c = try context.contractValue(port["contract_ref"], true)
                        let supplies = context.inputSupplies[R2Registry.canonicalKey(.array([.string(node["id"].text), port["name"]]))] ?? []
                        if c["kind"].text == "emission_list" {
                            guard supplies.count == 1, supplies[0].source["kind"].text == "policy" else { try R2Registry.fail(at) }
                            let policy = try r.get(c["policy_ref"], ["policy"], at)
                            if policy == nil || policy!.value["combine"]["kind"].text != "authored"
                                || policy!.value["combine"]["merge_node_ref"]["id"].text != node["id"].text
                                || policy!.value["combine"]["input_port"].text != port["name"].text { try R2Registry.fail(at) }
                        } else {
                            if supplies.isEmpty { try R2Registry.fail(at) }
                            if c != .null { try R2Values.completeBindings(c["shape"], supplies.map { $0.path }, at) }
                        }
                    }
                }
                if case .array(let outputList) = nodePorts.outputs {
                    for port in outputList { _ = try context.contractValue(port["contract_ref"], false) }
                }
            }
            try acyclic(context.graph, at)
            for binding in context.plan["result_bindings"].list {
                let source = try context.endpoint(binding["from"], "output")
                if !context.round(source.node["id"].text).isEmpty { try R2Registry.fail(at) }
                try R2Values.compatible(source.contract, try R2Values.projected(judgment["result_contract"], binding["field_path"].list.map { $0.text }, at) ?? .null, at)
            }
            try R2Values.completeBindings(judgment["result_contract"]["shape"], context.plan["result_bindings"].list.map { $0["field_path"].list.map { $0.text } }, at)
            var contributing = Set(context.plan["result_bindings"].list.map { $0["from"]["node_ref"]["id"].text })
            var reverse: [String: [String]] = [:]
            for id in context.nodes.keys { reverse[id] = [] }
            for (from, tos) in context.graph { for to in tos { reverse[to]!.append(from) } }
            for node in context.nodes.values where node["kind"].text == "feedback" {
                for update in node["updates"].list { reverse[update["next_input"]["node_ref"]["id"].text]!.append(update["from"]["node_ref"]["id"].text) }
            }
            var queue = Array(contributing)
            var cursor = 0
            while cursor < queue.count {
                for next in reverse[queue[cursor]] ?? [] where !contributing.contains(next) { contributing.insert(next); queue.append(next) }
                cursor += 1
            }
            context.contributing = contributing
            var methods = Set<String>()
            for id in contributing { for method in context.instanceMethods[id] ?? [] { methods.insert(method) } }
            context.methods = methods
        }
        var callGraph: [String: Set<String>] = [:]
        for judgment in payload["judgments"].list { callGraph[judgment["id"].text] = [] }
        for context in contexts.values { for (id, targets) in context.callTargets { callGraph[id]!.formUnion(targets) } }
        try acyclic(callGraph, "/payload/judgments/method/plan")
        var settled: [String: Set<String>] = [:]
        func actualMethods(_ id: String) throws -> Set<String> {
            if let cached = settled[id] { return cached }
            let judgment = payload["judgments"].list.first { $0["id"].text == id }!
            let context = contexts.get(id)
            var out = Set<String>()
            if context == nil {
                out.insert(judgment["method"]["method"]["term"].text)
            } else {
                for node in context!.nodes.values where context!.contributing.contains(node["id"].text) {
                    if node["kind"].text == "use" {
                        out.insert((try r.get(node["unit_ref"], ["unit"], context!.at))!.value["method"].text)
                    }
                    if node["kind"].text == "judgment_use" {
                        if let target = try r.get(R2Registry.qualified(node["judgment_ref"]), ["judgment"], context!.at) {
                            for method in try actualMethods(target.target["id"].text) { out.insert(method) }
                        }
                    }
                }
            }
            settled[id] = out
            return out
        }
        for judgment in payload["judgments"].list {
            guard let context = contexts.get(judgment["id"].text) else { continue }
            let methods = try actualMethods(judgment["id"].text)
            let external = r.unresolved.contains { entry in
                entry.mandatory && (try? r.get(entry.source, nil, context.at))??.judgment.text == judgment["id"].text
            }
            if judgment["method"]["method"]["term"].text == "composite" {
                if methods.count < 2 && !external { try R2Registry.fail(context.at) }
            } else if methods.contains(where: { $0 != judgment["method"]["method"]["term"].text }) {
                try R2Registry.fail(context.at)
            }
        }
        for record in r.ordered where record.target["kind"].text == "contract" && record.value["kind"].text == "emission_list" {
            let policy = try r.get(record.value["policy_ref"], ["policy"], record.path)
            if policy == nil || policy!.value["combine"]["kind"].text != "authored" { try R2Registry.fail(record.path) }
            guard let context = contexts.get(policy!.judgment.text), let merge = context.nodes.get(R2Registry.canonicalKey(policy!.value["combine"]["merge_node_ref"]["id"])), merge["kind"].text == "use" else {
                try R2Registry.fail(record.path)
            }
            let unit = (try r.get(merge["unit_ref"], ["unit"], record.path))!.value
            var count = 0
            for judgment in payload["judgments"].list {
                for candidate in judgment["method"]["units"].list {
                    for port in candidate["inputs"].list + candidate["outputs"].list where r.identity(port["contract_ref"]) == r.identity(record.target) {
                        count += 1
                        if candidate["id"].text != unit["id"].text || !candidate["inputs"].list.contains(where: { $0 == port }) || port["name"].text != policy!.value["combine"]["input_port"].text {
                            try R2Registry.fail(record.path)
                        }
                    }
                }
            }
            let useCount = context.nodes.values.filter { $0["kind"].text == "use" && $0["unit_ref"]["id"].text == unit["id"].text }.count
            if count != 1 || useCount != 1 { try R2Registry.fail(record.path) }
        }
    }
}
