import Foundation

// The 0.5-generation R2 semantics (r2-semantics.js, @aikdna/kdna-core@0.36.0):
// the whole-read validation pass that re-links the registry while checking
// every authored rule — applies/covers scopes, contracts and value shapes,
// component bodies, method roles, judgments with units and bindings, ports
// and result compatibility, relationships, dependencies, examples (incl. the
// partial-outcome entry ordering), revisions, attributions and closures.
//
// The released `scope` parameter gates the partial-read flows: only loaded
// judgments (and records owned by them) are actively validated, the registry
// comes from the structurally observed registration inputs, and the plan
// graph sees the active judgment subset with the complete-judgment set for
// emission policies. scope == nil is the whole-read path.
struct R2ValidationScope {
    let registry: R2Registry.Registry
    let loadedJudgments: Set<String>
    let completeJudgments: [J]
    let requireCompletePolicyUses: (R2Registry.Record) throws -> Void
}
enum R2Semantics {
    static func validateR2(_ manifest: J, _ payload: J, _ entries: [KDNAKey: Data], _ scope: R2ValidationScope? = nil) throws -> R2Registry.Registry {
        let r: R2Registry.Registry
        if let scope { r = scope.registry } else { r = try R2Registry.createRegistry(manifest, payload) }
        let activeRecord: (R2Registry.Record) -> Bool = { record in
            scope == nil || record.judgment == .null || scope!.loadedJudgments.contains(record.judgment.text)
        }
        let activeJudgments = scope == nil ? payload["judgments"].list
            : payload["judgments"].list.filter { scope!.loadedJudgments.contains($0["id"].text) }
        let contract = try SemanticContract.loadedContract.get()
        let definition = contract["r2_semantics"], termsRegistry = contract["core_terms"]
        if definition == .null { try R2Registry.fail("/payload/profile_version") }
        let roles = definition["method_roles"]
        let own: (R2Registry.Record, J, Bool, [String]?, String?) throws -> R2Registry.Record? = { record, target, mandatory, kinds, referenceRole in
            try r.link(record.target, target, mandatory, kinds, record.path, referenceRole)
        }
        func resolve(_ target: J, _ kind: String, _ field: String) throws -> R2Registry.Record? {
            try r.get(target, [kind], field)
        }
        func normalContract(_ target: J, _ field: String) throws -> J {
            guard let record = try resolve(target, "contract", field) else { return .null }
            if try record.checkedValue()["kind"].text == "emission_list" { try R2Registry.fail(field) }
            return try record.checkedValue()
        }
        func applies(_ scope: J, _ field: String) throws -> Set<String> {
            if scope["kind"].text == "asset" { return Set(payload["judgments"].list.map { $0["id"].text }) }
            let refs = scope["judgment_refs"].list
            if scope["kind"].text != "judgments" || refs.isEmpty || Set(refs.map { $0.text }).count != refs.count { try R2Registry.fail(field) }
            for id in refs { _ = try resolve(R2Registry.ref("judgment", id.text), "judgment", field) }
            return Set(refs.map { $0.text })
        }
        func covers(_ scope: J, _ id: String, _ field: String) throws -> Bool { try applies(scope, field).contains(id) }
        func subset(_ a: J, _ b: J, _ field: String) throws {
            let left = try applies(a, field), right = try applies(b, field)
            if left.contains(where: { !right.contains($0) }) { try R2Registry.fail(field) }
        }
        let assetRecord = try resolve(r.asset, "asset", "/payload")
        if payload["declarations"]["highest_question"]["state"].text != "provided" { try R2Registry.fail("/payload/declarations/highest_question") }
        for key in ["worldview", "value_order", "role"] where payload["declarations"].has(key) { try R2Registry.fail("/payload/declarations/" + key) }
        let readingOrder = payload["reading_order"].list
        if Set(readingOrder.map { $0.text }).count != readingOrder.count { try R2Registry.fail("/payload/reading_order") }
        for id in readingOrder { _ = try resolve(R2Registry.ref("judgment", id.text), "judgment", "/payload/reading_order") }
        for target in payload["kernel"]["foundation_refs"].list {
            let material = try own(assetRecord!, target, !r.local(target), ["material"], nil)
            if let material, !["foundation", "premise"].contains((try material.checkedValue())["kind"].text) { try R2Registry.fail("/payload/kernel/foundation_refs") }
        }
        for record in r.ordered where activeRecord(record) && record.target["kind"].text == "contract" {
            let recordValue = try record.checkedValue()
            try R2Values.validateContract(recordValue, record.path)
            if recordValue["kind"].text != "emission_list" {
                for term in [recordValue["form"]] + recordValue["allowed_result_types"].list {
                    let vocabulary = term["vocabulary"].text, name = term["term"].text
                    if vocabulary != "author" && !termsRegistry["answer_type"].list.contains(where: { $0.text == name }) { try R2Registry.fail(record.path) }
                }
            }
        }
        var terms = Set<String>()
        for record in r.ordered {
            if !activeRecord(record) { continue }
            let v = try record.checkedValue(), kind = record.target["kind"].text, at = record.path
            if kind == "material" {
                if ["definition", "foundation", "premise"].contains(v["kind"].text) { _ = try applies(v["applies_to"], at) }
                if v["kind"].text == "definition" {
                    let term = v["term"].text
                    if term.isEmpty || terms.contains(term) { try R2Registry.fail(at) }
                    terms.insert(term)
                }
                if v["resource_ref"] != .null { _ = try own(record, R2Registry.ref("resource", v["resource_ref"].text), true, ["resource"], nil) }
                for id in v["source_refs"].list { _ = try own(record, R2Registry.ref("source", id.text), true, ["source"], nil) }
            } else if kind == "resource" {
                guard let bytes = entries[KDNAKey(v["entry"].text)] else { try R2Registry.fail(at) }
                if sha(bytes) != v["digest"].text { try R2Registry.fail(at) }
            } else if kind == "shared_declaration" {
                _ = try applies(v["applies_to"], at)
                for id in v["subject"]["actor_ids"].list { _ = try own(record, R2Registry.ref("actor", id.text), true, ["actor"], nil) }
                if v["kind"].text == "role" && !v["value"].fields.values.contains(where: { $0["state"].text == "provided" }) { try R2Registry.fail(at) }
            } else if kind == "condition" {
                _ = try own(record, v["owner_ref"], false, ["asset", "judgment", "policy", "exception"], nil)
                let c = v["expression"]["kind"].text == "external_evaluator" ? v["expression"]["declaration"] : v["expression"]
                for operand in c["operands"].list where operand["kind"].text == "dependency" {
                    _ = try own(record, R2Registry.ref("dependency", operand["dependency_ref"].text), true, ["dependency"], nil)
                }
            } else if kind == "result" {
                _ = try own(record, R2Registry.ref("contract", v["contract_ref"].text), true, ["contract"], nil)
            } else if kind == "component" {
                if v.has("statement") == v.has("content_ref") { try R2Registry.fail(at) }
                if v.has("content_ref") {
                    let target = try own(record, v["content_ref"], true, ["result", "material", "shared_declaration", "reason", "component"], nil)
                    if let target, target.target["kind"].text == "result" {
                        let targetValue = try target.checkedValue()
                        if !(target.judgment.text == record.judgment.text && targetValue["value"]["kind"].text == "text") {
                            try R2Registry.fail(at + "/content_ref")
                        }
                    }
                }
                for target in v["material_refs"].list { _ = try own(record, target, true, ["material"], nil) }
            } else if kind == "reason" {
                _ = try own(record, R2Registry.ref("judgment", v["judgment_ref"].text), true, ["judgment"], nil)
                for id in v["component_refs"].list { _ = try own(record, R2Registry.ref("component", id.text), true, ["component"], nil) }
            } else if kind == "source_use" {
                _ = try own(record, R2Registry.ref("source", v["source_ref"].text), true, ["source"], nil)
                let targetKind = v["target_kind"].text == "method_component" ? "component" : v["target_kind"].text
                let actual = try own(record, R2Registry.ref(targetKind, v["target_ref"].text), true, ["judgment", "reason", "material", "component", "example", "example_result", "shared_declaration"], nil)
                if let actual { _ = try r.link(actual.target, record.target, true, nil, record.path, nil) }
            } else if kind == "boundary" {
                _ = try applies(v["applies_to"], at)
                _ = try own(record, R2Registry.ref("actor", v["declared_by"].text), true, ["actor"], nil)
                if record.judgment != .null && (v["applies_to"]["kind"].text != "judgments" || v["applies_to"]["judgment_refs"].list.count != 1 || v["applies_to"]["judgment_refs"].list[0].text != record.judgment.text) { try R2Registry.fail(at) }
                if record.activation["kind"].text == "exception" && !v["exception_refs"].list.isEmpty { try R2Registry.fail(at) }
                for id in v["exception_refs"].list {
                    let exception = try own(record, R2Registry.ref("exception", id.text), true, ["exception"], nil)
                    if exception == nil { try R2Registry.fail(at) }
                    if (try exception!.checkedValue())["boundary_ref"].text != v["id"].text { try R2Registry.fail(at) }
                }
            } else if kind == "exception" {
                if v["boundary_ref"] == .null { try R2Registry.fail(at) }
                let boundary = try own(record, R2Registry.ref("boundary", v["boundary_ref"].text), true, ["boundary"], nil)
                if boundary == nil { try R2Registry.fail(at) }
                let boundaryValue = try boundary!.checkedValue()
                if boundary!.activation["kind"].text != "always" || !boundaryValue["exception_refs"].list.contains(where: { $0.text == v["id"].text }) { try R2Registry.fail(at) }
                try subset(v["applies_to"], boundaryValue["applies_to"], at)
                if record.judgment != .null && (v["applies_to"]["kind"].text != "judgments" || v["applies_to"]["judgment_refs"].list.count != 1 || v["applies_to"]["judgment_refs"].list[0].text != record.judgment.text) { try R2Registry.fail(at) }
                _ = try own(record, v["when"], true, ["condition"], nil)
                if v["effect"]["kind"].text == "replace_limit" {
                    let replacement = try own(record, R2Registry.ref("boundary", v["effect"]["replacement"]["id"].text), true, ["boundary"], nil)
                    if !R2Values.equal(replacement?.owner ?? .null, record.target) || !R2Values.equal(v["effect"]["replacement"]["applies_to"], v["applies_to"]) { try R2Registry.fail(at) }
                }
            }
        }
        // Component content cycles are illegal; common semantic-reference cycles
        // are legal and bounded by fixed-point closure.
        var contentDone = Set<String>(), contentActive = Set<String>()
        func componentBody(_ record: R2Registry.Record) throws {
            let id = r.identity(record.target)
            if contentDone.contains(id) { return }
            if contentActive.contains(id) { try R2Registry.fail(record.path + "/content_ref") }
            contentActive.insert(id)
            if try record.checkedValue()["content_ref"]["kind"].text == "component" {
                if let next = try resolve(try record.checkedValue()["content_ref"], "component", record.path) { try componentBody(next) }
            }
            contentActive.remove(id); contentDone.insert(id)
        }
        for record in r.ordered where activeRecord(record) && record.target["kind"].text == "component" { try componentBody(record) }
        func methodRoles(_ method: String, _ components: [J], _ field: String) throws {
            let spec = roles[method]
            if spec == .null { try R2Registry.fail(field) }
            let required = spec["required"].list.map { $0.text }
            let allowed = Set(required + spec["optional"].list.map { $0.text })
            var used = Set<String>()
            for component in components {
                let role = component["role"].text
                if !allowed.contains(role) || used.contains(role) { try R2Registry.fail(field) }
                if component["method"]["term"].text != method { try R2Registry.fail(field) }
                used.insert(role)
            }
            if required.contains(where: { !used.contains($0) }) { try R2Registry.fail(field) }
        }
        for judgment in activeJudgments {
            let record = try resolve(R2Registry.ref("judgment", judgment["id"].text), "judgment", "/payload")!
            let at = record.path
            try R2Values.validateResult(judgment)
            for child in r.ordered where child.judgment.text == judgment["id"].text && child.key != record.key {
                _ = try own(record, child.target, true, nil, nil)
            }
            for id in judgment["subject"]["actor_ids"].list { _ = try own(record, R2Registry.ref("actor", id.text), true, ["actor"], nil) }
            for id in judgment["material_refs"].list { _ = try own(record, R2Registry.ref("material", id.text), true, ["material"], nil) }
            for id in judgment["reason_refs"].list {
                let reason = try own(record, R2Registry.ref("reason", id.text), true, ["reason"], nil)
                if try reason?.checkedValue()["judgment_ref"].text != judgment["id"].text { try R2Registry.fail(at) }
            }
            if !definition["answer_kinds"].list.contains(where: { $0.text == judgment["answer_kind"].text })
                || !definition["method_kinds"].list.contains(where: { $0.text == judgment["method"]["method"]["term"].text }) { try R2Registry.fail(at) }
            if judgment["core_expression"]["kind"].text == "result_text" {
                if judgment["form"].text != "conclusion" || judgment["result"]["value"]["kind"].text != "text" { try R2Registry.fail(at + "/core_expression") }
            } else {
                for target in judgment["core_expression"]["qualification_refs"].list {
                    _ = try own(record, target, true, ["condition", "boundary", "material", "shared_declaration"], nil)
                }
            }
            if judgment["answer_kind"].text == "composite" {
                let parts = judgment["answer_parts"].list
                _ = try R2Values.unique(parts, "id", at); _ = try R2Values.unique(parts, "output_field", at)
                if parts.count < 2 || Set(parts.map { $0["kind"].text }).count < 2 || judgment["result_contract"]["shape"]["kind"].text != "record" { try R2Registry.fail(at) }
                for part in parts {
                    if part["kind"].text == "composite" || !definition["answer_kinds"].list.contains(where: { $0.text == part["kind"].text }) { try R2Registry.fail(at) }
                    if (part["kind"].text == "other") != part.has("other") { try R2Registry.fail(at) }
                    let field = judgment["result_contract"]["shape"]["fields"].list.first { $0["name"].text == part["output_field"].text }
                    if field?["required"].boolean != true { try R2Registry.fail(at) }
                }
            } else if judgment.has("answer_parts") { try R2Registry.fail(at) }
            if (judgment["answer_kind"].text == "other") != judgment.has("answer_other") { try R2Registry.fail(at) }
            let method = judgment["method"], term = method["method"]["term"].text
            if (term == "other") != method["method"].has("other") { try R2Registry.fail(at + "/method") }
            if method["plan"] != .null && !method.has("units") { try R2Registry.fail(at + "/method/units") }
            if method["plan"] == .null && (!method["units"].list.isEmpty || term == "composite") { try R2Registry.fail(at + "/method/plan") }
            if method["plan"] == .null { try methodRoles(term, method["components"].list, at + "/method/components") }
            var referencedComponents = Set<String>()
            for unit in method["units"].list {
                if unit["method"].text == "composite" || !definition["method_kinds"].list.contains(where: { $0.text == unit["method"].text }) { try R2Registry.fail(at) }
                if (unit["method"].text == "other") != unit.has("other") { try R2Registry.fail(at) }
                var components: [J] = []
                for id in unit["component_refs"].list {
                    let c = try resolve(R2Registry.ref("component", id.text), "component", at)!
                    if c.judgment.text != judgment["id"].text { try R2Registry.fail(at) }
                    referencedComponents.insert(id.text)
                    _ = try r.link(R2Registry.ref("unit", unit["id"].text), c.target, true, nil, at, nil)
                    components.append(try c.checkedValue())
                }
                if Set(unit["component_refs"].list.map { $0.text }).count != unit["component_refs"].list.count { try R2Registry.fail(at) }
                try methodRoles(unit["method"].text, components, at + "/method/units")
                for port in unit["inputs"].list + unit["outputs"].list { _ = try r.link(R2Registry.ref("unit", unit["id"].text), port["contract_ref"], true, ["contract"], at, nil) }
                _ = try R2Values.unique(unit["inputs"].list, "name", at); _ = try R2Values.unique(unit["outputs"].list, "name", at)
            }
            if method["plan"] != .null && method["components"].list.contains(where: { !referencedComponents.contains($0["id"].text) }) { try R2Registry.fail(at + "/method/components") }
            var seenBindings = Set<String>()
            for binding in method["bindings"].list {
                let field = at + "/method/bindings"
                let component = try resolve(R2Registry.ref("component", binding["component_ref"].text), "component", field)!
                if component.judgment.text != judgment["id"].text { try R2Registry.fail(field) }
                if binding.has("target") {
                    if binding.has("target_ref") || binding["target"].has("asset") { try R2Registry.fail(field) }
                    _ = try r.link(component.target, binding["target"], true, definition["native_binding"]["target_kinds"].list.map { $0.text }, field, nil)
                } else if binding["target_ref"].text != judgment["id"].text { try R2Registry.fail(field) }
                let identity = R2Registry.canonicalKey(.array([binding["component_ref"], binding["role"], binding.has("target") ? .array([binding["target"]["kind"], binding["target"]["id"]]) : binding["target_ref"]]))
                if !seenBindings.insert(identity).inserted { try R2Registry.fail(field) }
            }
            for condition in judgment["formation_rule"]["condition_refs"].list { _ = try own(record, condition, true, ["condition"], nil) }
            let inputs = try R2Values.unique(judgment["inputs"].list, "name", at), ports = try R2Values.unique(judgment["ports"].list, "name", at)
            for input in inputs.values {
                _ = try own(record, input["contract_ref"], true, ["contract"], nil)
                _ = try normalContract(input["contract_ref"], at)
            }
            for port in ports.values {
                _ = try own(record, port["contract_ref"], true, ["contract"], nil)
                let c = try normalContract(port["contract_ref"], at)
                if port["direction"].text == "input" {
                    guard let input = inputs.get(R2Registry.canonicalKey(port["input_role"])), !port.has("result_field") else { try R2Registry.fail(at) }
                    try R2Values.compatible(try normalContract(input["contract_ref"], at), c, at)
                } else {
                    if !port.has("result_field") || port.has("input_role") { try R2Registry.fail(at) }
                    try R2Values.compatible(try R2Values.projected(judgment["result_contract"], port["result_field"] == .null ? [] : [port["result_field"].text], at) ?? .null, c, at)
                }
            }
            var used = [String: Set<String>]()
            for use in judgment["content_uses"].list {
                let target = try own(record, use["target"], true, ["material", "shared_declaration"], nil)
                let id = r.identity(use["target"]), role = use["role"].text
                var previous = used[id] ?? Set<String>()
                if previous.contains(role) || (role == "adopt" && previous.contains("oppose")) || (role == "oppose" && previous.contains("adopt")) { try R2Registry.fail(at) }
                previous.insert(role); used[id] = previous
                if let target, role == "adopt", (try target.checkedValue())["applies_to"] != .null, !(try covers((try target.checkedValue())["applies_to"], judgment["id"].text, at)) { try R2Registry.fail(at) }
                if let target, target.target["kind"].text == "shared_declaration", role == "oppose", try covers(try target.checkedValue()["applies_to"], judgment["id"].text, at) { try R2Registry.fail(at) }
            }
            for shared in payload["shared_declarations"].list where try covers(shared["applies_to"], judgment["id"].text, at) {
                _ = try own(record, R2Registry.ref("shared_declaration", shared["id"].text), true, nil, nil)
            }
            for material in payload["materials"].list {
                if !["foundation", "premise"].contains(material["kind"].text) { continue }
                if try covers(material["applies_to"], judgment["id"].text, at) {
                    _ = try own(record, R2Registry.ref("material", material["id"].text), true, nil, nil)
                }
            }
            for boundary in R2Registry.values(payload["declarations"]["boundaries"]) where try covers(boundary["applies_to"], judgment["id"].text, at) {
                _ = try own(record, R2Registry.ref("boundary", boundary["id"].text), true, nil, nil)
            }
            for replacement in judgment["lifecycle"]["superseded_by"].list {
                _ = try own(record, R2Registry.qualified(replacement), true, ["judgment"], "lifecycle_replacement")
            }
        }
        for relation in payload["relationships"].list {
            let record = try resolve(R2Registry.ref("relationship", relation["id"].text), "relationship", "/payload")!
            let tupleDeclared = definition["relationship_tuples"][relation["kind"]["term"].text]
            let tuple = tupleDeclared == .null ? nil : [tupleDeclared["direction"].text, tupleDeclared["roles"].list[0].text, tupleDeclared["roles"].list[1].text, tupleDeclared["operator"].text, tupleDeclared["effect"].text]
            guard let tuple, relation["direction"].text == tuple[0], relation["operator"]["term"].text == tuple[3], relation["effect"]["term"].text == tuple[4], relation["participants"].list.count == 2 else { try R2Registry.fail(record.path) }
            var participants = R2Registry.OrderedMap<J>()
            for participant in relation["participants"].list {
                var updated = participant
                updated["role"] = participant["role"]["term"]
                let role = updated["role"].text
                if participants.get(role) != nil { try R2Registry.fail(record.path) }
                participants.set(role, updated)
            }
            guard let firstParticipant = participants.get(tuple[1]), let secondParticipant = participants.get(tuple[2]) else { try R2Registry.fail(record.path) }
            if firstParticipant["judgment_ref"].text == secondParticipant["judgment_ref"].text { try R2Registry.fail(record.path) }
            for participant in participants.values {
                _ = try resolve(R2Registry.ref("judgment", participant["judgment_ref"].text), "judgment", record.path)
                _ = try r.link(R2Registry.ref("judgment", participant["judgment_ref"].text), record.target, true, nil, record.path, nil)
                _ = try own(record, R2Registry.ref("judgment", participant["judgment_ref"].text), false, ["judgment"], nil)
            }
            let first = R2Registry.ref("judgment", firstParticipant["judgment_ref"].text), second = R2Registry.ref("judgment", secondParticipant["judgment_ref"].text)
            if relation["kind"]["term"].text == "conflict" {
                _ = try r.link(first, second, true, nil, record.path, nil)
                _ = try r.link(second, first, true, nil, record.path, nil)
            } else if ["support", "qualify"].contains(relation["kind"]["term"].text) {
                _ = try r.link(second, first, true, nil, record.path, nil)
            }
        }
        for dependency in payload["dependencies"].list {
            let record = try resolve(R2Registry.ref("dependency", dependency["id"].text), "dependency", "/payload")!
            let at = record.path
            let consumer = try resolve(R2Registry.ref("judgment", dependency["consumer_judgment_ref"].text), "judgment", at)!
            let cport = (try consumer.checkedValue())["ports"].list.first { $0["name"].text == dependency["consumer_port"].text && $0["direction"].text == "input" }
            if cport == nil || cport!["input_role"].text != dependency["input_role"].text { try R2Registry.fail(at) }
            _ = try own(record, cport!["contract_ref"], true, ["contract"], nil)
            _ = try own(record, consumer.target, false, ["judgment"], nil)
            _ = try r.link(consumer.target, record.target, dependency["required"].boolean, nil, at, nil)
            if dependency["producer"]["kind"].text == "judgment_result" {
                let producer = try own(record, R2Registry.ref("judgment", dependency["producer"]["judgment_ref"].text), true, ["judgment"], nil)!
                let producerValue = try producer.checkedValue()
                let pport = producerValue["ports"].list.first { $0["name"].text == dependency["producer_port"].text && $0["direction"].text == "output" }
                if pport == nil || producerValue["result_contract"]["id"].text != dependency["producer"]["result_contract_ref"].text { try R2Registry.fail(at) }
                try R2Values.compatible(try normalContract(pport!["contract_ref"], at), try normalContract(cport!["contract_ref"], at), at)
            } else {
                if dependency.has("producer_port") { try R2Registry.fail(at) }
                _ = try own(record, R2Registry.ref("source", dependency["producer"]["source_ref"].text), true, ["source"], nil)
            }
        }
        if scope == nil {
            try R2Plan.checkPlans(payload, r, normalContract, nil)
        } else {
            var scopedPayload = payload
            scopedPayload["judgments"] = .array(activeJudgments)
            try R2Plan.checkPlans(scopedPayload, r, normalContract, scope)
        }
        for example in payload["examples"].list {
            let record = try resolve(R2Registry.ref("example", example["id"].text), "example", "/payload")!
            let at = record.path
            for target in example["input_refs"].list {
                let input = try own(record, target, true, nil, nil)
                if let input, input.target["kind"].text != "asset" { _ = try r.link(input.target, record.target, false, ["example"], at) }
            }
            for target in example["source_refs"].list { _ = try own(record, target, true, ["source"], nil) }
            for target in example["material_refs"].list { _ = try own(record, target, true, ["material"], nil) }
            for target in example["adopted_judgments"].list {
                let adopted = try own(record, R2Registry.qualified(target), false, ["judgment"], nil)
                if let adopted { _ = try r.link(adopted.target, record.target, false, ["example"], at) }
            }
            for result in example["results"].list {
                let item = try resolve(R2Registry.ref("example_result", result["id"].text), "example_result", at)!
                _ = try own(record, item.target, true, nil, nil)
                if (result["kind"].text == "observed" || result["observation_kind"].text == "observed") && example["kind"].text == "illustrative" { try R2Registry.fail(at) }
                if ["expected", "observed"].contains(result["kind"].text) {
                    _ = try own(item, result["contract_ref"], true, ["contract"], nil)
                    let contract = try normalContract(result["contract_ref"], at)
                    if contract != .null { try R2Values.valueFor(contract, result["value"], at) }
                    if result["comparison_ref"] != .null {
                        let comparison = try own(item, result["comparison_ref"], true, ["example_result"], nil)
                        let comparisonValue = try comparison?.checkedValue()
                        if result["kind"].text != "observed" || comparison?.owner["id"].text != example["id"].text || comparisonValue?["kind"].text != "expected"
                            || r.identity(comparison!.rawValue["contract_ref"]) != r.identity(result["contract_ref"]) { try R2Registry.fail(at) }
                    }
                } else if result["kind"].text == "partial" {
                    let outcome = result["outcome"]
                    let policy = try own(item, outcome["policy_ref"], true, ["policy"], nil)
                    if outcome["kind"].text != "partial" || policy == nil { try R2Registry.fail(at) }
                    let policyValue = try policy!.checkedValue()
                    if policyValue["match"].text != "all_matches"
                        || policyValue["combine"]["kind"].text != "collect" || policyValue["on_undetermined"]["kind"].text != "partial"
                        || r.identity(outcome["item_contract_ref"]) != r.identity(policyValue["combine"]["item_contract_ref"]) { try R2Registry.fail(at) }
                    _ = try own(item, outcome["item_contract_ref"], true, ["contract"], nil)
                    let contract = try normalContract(outcome["item_contract_ref"], at)
                    var seen = Set<String>()
                    for pending in outcome["pending"].list {
                        let entry = try own(item, pending, true, ["branch_entry"], nil)
                        if entry?.owner["id"].text != policy!.target["id"].text || !seen.insert(entry!.target["id"].text).inserted { try R2Registry.fail(at) }
                    }
                    if outcome["pending"].list.isEmpty { try R2Registry.fail(at) }
                    func producerKey(_ value: J) -> String {
                        value["kind"] != .null ? r.identity(value) : R2Registry.canonicalKey(.array([.string(r.identity(value["node_ref"])), value["port"], value["field_path"]]))
                    }
                    var declared = policyValue["entries"].list
                    if policyValue["combine"]["order"].text == "priority" {
                        declared.sort { $0["priority"].numeric < $1["priority"].numeric }
                    }
                    var order: [String: Int] = [:]
                    for (index, entry) in declared.enumerated() { order[entry["id"].text] = index }
                    var emitted: [String: J] = [:]
                    var lastEmission = -1
                    for emission in outcome["confirmed"].list {
                        if contract != .null { try R2Values.valueFor(contract, emission["value"], at) }
                        let identity = producerKey(emission["producer"])
                        if let earlier = emitted[identity], !R2Values.equal(earlier, emission["value"]) || policyValue["combine"]["duplicates"].text == "producer_identity" { try R2Registry.fail(at) }
                        emitted[identity] = emission["value"]
                        if policyValue["combine"]["duplicates"].text == "preserve" && emission["entry_refs"].list.count != 1 { try R2Registry.fail(at) }
                        var lastEntry = -1
                        for target in emission["entry_refs"].list {
                            let entry = try own(item, target, true, ["branch_entry"], nil)
                            if entry?.owner["id"].text != policy!.target["id"].text || !seen.insert(entry!.target["id"].text).inserted { try R2Registry.fail(at) }
                            let entryValue = try entry!.checkedValue()
                            let producer = entryValue["then"]["kind"].text == "candidate" ? entryValue["then"]["candidate_ref"] : entryValue["then"]["from"]
                            if producerKey(producer) != identity { try R2Registry.fail(at) }
                            if entryValue["then"]["kind"].text == "candidate" {
                                if !R2Values.equal(try resolve(producer, "candidate", at)!.checkedValue()["value"], emission["value"]) { try R2Registry.fail(at) }
                            }
                            if order[entry!.target["id"].text]! <= lastEntry { try R2Registry.fail(at) }
                            if lastEntry == -1 {
                                if order[entry!.target["id"].text]! <= lastEmission { try R2Registry.fail(at) }
                                lastEmission = order[entry!.target["id"].text]!
                            }
                            lastEntry = order[entry!.target["id"].text]!
                        }
                    }
                }
            }
        }
        for revision in manifest["history"]["entries"].list {
            let record = try resolve(R2Registry.ref("revision", revision["id"].text), "revision", "/manifest/history/entries")!
            for target in revision["affected_refs"].list {
                let affected = try own(record, target, false, nil, nil)
                if let affected { _ = try r.link(affected.target, record.target, false, ["revision"], record.path) }
            }
            for id in revision["actor_refs"].list { _ = try own(record, R2Registry.ref("actor", id.text), true, ["actor"], nil) }
            if revision["previous"] != .null { _ = try own(record, revision["previous"], false, ["revision"], nil) }
        }
        for claim in R2Registry.values(payload["attributions"]) {
            for id in claim["actor_ids"].list { _ = try own(assetRecord!, R2Registry.ref("actor", id.text), true, ["actor"], nil) }
        }
        for boundary in R2Registry.values(payload["declarations"]["boundaries"]) {
            _ = try own(assetRecord!, R2Registry.ref("boundary", boundary["id"].text), false, ["boundary"], nil)
        }
        for misuse in payload["misuse"].list { _ = try own(assetRecord!, R2Registry.ref("misuse", misuse["id"].text), true, ["misuse"], nil) }
        return r
    }
}
