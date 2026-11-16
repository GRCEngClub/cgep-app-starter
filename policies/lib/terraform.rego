package lib.tf

import rego.v1

# All managed resources of one type, read from the plan's configuration
managed(type) := {r |
    some r in input.configuration.root_module.resources
    r.mode == "managed"
    r.type == type
}

data_sources(type) := {r |
    some r in input.configuration.root_module.resources
    r.mode == "data"
    r.type == type
}

# true if resource r's <field> points at address addr
references(r, field, addr) if {
    some ref in object.get(r.expressions, [field, "references"], [])
    ref == addr
}

# the aws_iam_policy_document that resource r's <field> uses
policy_doc(r, field) := doc if {
    some doc in data_sources("aws_iam_policy_document")
    references(r, field, doc.address)
}
