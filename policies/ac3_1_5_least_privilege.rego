# METADATA
# title: IAM policies must follow least privilege
# description: >
#   GAP-07. Allow statements may not use wildcard actions ("*" or "service:*")
#   or the wildcard resource "*". Inline and managed IAM policies must be written
#   with aws_iam_policy_document so they can be checked at plan time. Attaching
#   AdministratorAccess or PowerUserAccess is not allowed.
# custom:
#   control_id: AC.L2-3.1.5
#   framework: CMMC Level 2 (NIST SP 800-171)
#   gap: GAP-07
#   severity: high
#   remediation: >
#     List the exact actions and resource ARNs in an aws_iam_policy_document and
#     point the role policy at its .json output.
package compliance.ac3_1_5_least_privilege

import data.lib.tf
import rego.v1

policy_resource_types := {"aws_iam_role_policy", "aws_iam_policy", "aws_iam_user_policy", "aws_iam_group_policy"}

broad_managed_policies := {
	"arn:aws:iam::aws:policy/AdministratorAccess",
	"arn:aws:iam::aws:policy/PowerUserAccess",
}

is_allow(st) if not st.effect

is_allow(st) if st.effect.constant_value == "Allow"

wildcard_action(a) if a == "*"

wildcard_action(a) if endswith(a, ":*")

sid_of(st) := st.sid.constant_value

sid_of(st) := "(no sid)" if not st.sid

has_doc(r) if count(tf.docs_for(r.expressions.policy)) > 0

deny contains msg if {
	some d in tf.policy_docs
	some st in d.expressions.statement
	is_allow(st)
	some a in st.actions.constant_value
	wildcard_action(a)
	msg := sprintf("[AC.L2-3.1.5] %s statement %s allows wildcard action %q (GAP-07)", [d.address, sid_of(st), a])
}

deny contains msg if {
	some d in tf.policy_docs
	some st in d.expressions.statement
	is_allow(st)
	"*" in st.resources.constant_value
	msg := sprintf("[AC.L2-3.1.5] %s statement %s allows wildcard resource \"*\" (GAP-07)", [d.address, sid_of(st)])
}

deny contains msg if {
	some t in policy_resource_types
	some r in tf.managed(t)
	not has_doc(r)
	msg := sprintf("[AC.L2-3.1.5] %s must use an aws_iam_policy_document so least privilege can be verified (GAP-07)", [r.address])
}

deny contains msg if {
	some r in tf.managed("aws_iam_role_policy_attachment")
	r.expressions.policy_arn.constant_value in broad_managed_policies
	msg := sprintf("[AC.L2-3.1.5] %s attaches an over-broad managed policy (GAP-07)", [r.address])
}
