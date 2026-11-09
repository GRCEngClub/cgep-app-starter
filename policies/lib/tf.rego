# Shared helpers for the capstone policies.
# Policies read the *configuration* section of `terraform show -json`, not the
# planned values: configuration keeps constants and references even when values
# are "known after apply", so the checks work on a fresh plan and on an
# incremental one.
package lib.tf

import rego.v1

resources := input.configuration.root_module.resources

# All managed resources of one type.
managed(type) := {r | some r in resources; r.mode == "managed"; r.type == type}

# All aws_iam_policy_document data sources (statically analysable policies).
policy_docs := {r | some r in resources; r.mode == "data"; r.type == "aws_iam_policy_document"}

# Reference strings inside one attribute expression.
refs(expr) := {x | some x in expr.references}

# True when the attribute is a non-empty list (constant or by reference).
nonempty(expr) if count(expr.references) > 0

nonempty(expr) if count(expr.constant_value) > 0

# True when the attribute points at a customer-managed key: a reference to an
# aws_kms_key / aws_kms_alias (resource or data source), or a literal KMS ARN.
# A missing key id (AWS-managed key) or "alias/aws/..." is NOT a CMK.
is_cmk(expr) if {
	some r in refs(expr)
	some prefix in {"aws_kms_key.", "aws_kms_alias.", "data.aws_kms_key.", "data.aws_kms_alias."}
	startswith(r, prefix)
}

is_cmk(expr) if startswith(expr.constant_value, "arn:aws:kms:")

# The aws_iam_policy_document data sources a "policy" attribute points at.
docs_for(expr) := {d | some r in refs(expr); some d in policy_docs; d.address == r}

# Buckets that hold CloudTrail audit logs, not PHI. They are exempt from the
# PHI-specific storage controls (CMK, versioning) and nothing else.
# Rationale: see WRITEUP.md, "Design decisions".
audit_log_buckets := {"aws_s3_bucket.trail"}
