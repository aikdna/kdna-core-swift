import Foundation

// node-order-index/1 decode: the stored representation metadata resolves its
// *_index fields through node_order and must validate as
// RepresentationMetadata06. Authority: section-metadata-codec.js `decode`
// (@aikdna/kdna-core@0.36.0); the encode side is produce-only and not
// ported. Both shape failures surface as METADATA_<name>_SHAPE and the range
// failure as METADATA_NODE_INDEX_RANGE, verbatim.
enum MetadataCodec {
    static func shape(_ name: String, _ value: J) throws -> J {
        do { return try SectionContract.validate(name, value) }
        catch is PublicFailure { throw PublicFailure("METADATA_" + name + "_SHAPE") }
    }
    static func decode(_ stored: J) throws -> J {
        var out = try shape("StoredRepresentationMetadata06", stored)
        let order = out["node_order"].list
        func node(_ index: J) throws -> J {
            let i = index.numeric
            guard isUInt(index), i >= 0, Int(i) < order.count else { throw PublicFailure("METADATA_NODE_INDEX_RANGE") }
            return order[Int(i)]
        }
        out["references"] = .array(try out["references"].list.map { reference in
            var item = reference
            item.remove("source_node_index"); item.remove("target_node_index")
            item["source_node"] = try node(reference["source_node_index"])
            item["target_node"] = try node(reference["target_node_index"])
            return item
        })
        out["asset_index"] = .array(try out["asset_index"].list.map { entry in
            var item = entry
            item.remove("node_index")
            item["node_ref"] = try node(entry["node_index"])
            return item
        })
        out["mandatory_closures"] = .array(try out["mandatory_closures"].list.map { closure in
            var item = closure
            item.remove("node_indices")
            item["node_ids"] = .array(try closure["node_indices"].list.map { try node($0) })
            return item
        })
        out["asset_closure"] = .array(try out["asset_closure"].list.map { try node($0) })
        out.remove("codec")
        return try shape("RepresentationMetadata06", out)
    }
}
