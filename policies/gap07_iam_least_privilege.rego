# policies/gap07_iam_least_privilege.rego
# METADATA
# title: GAP-07 - Lambda IAM role must not use service wildcards
# description: "IAM policies on the workload must name specific actions. Service-level wildcards like s3:* or dynamodb:* violate least privilege."
# custom:
#   gap_id: GAP-07
#   hipaa: 164.312(a)(1)
#   control_id: AC-6
#   severity: critical
package capstone.gap07

import rego.v1

deny contains msg if {
	some r in input.planned_values.root_module.resources
	r.type == "aws_iam_role_policy"
	some action in policy_actions(r)
	is_service_wildcard(action)
	msg := sprintf(
		"[GAP-07][HIPAA 164.312(a)(1)] %s: policy grants %s — a service-level wildcard. PHI access must be least-privilege. Remediation: replace with the specific actions the Lambda needs (e.g. dynamodb:PutItem, s3:PutObject).",
		[r.address, action],
	)
}

policy_actions(r) := actions if {
	doc := json.unmarshal(r.values.policy)
	actions := {a |
		some stmt in doc.Statement
		some a in as_array(stmt.Action)
	}
}

as_array(x) := x if is_array(x)
as_array(x) := [x] if is_string(x)

is_service_wildcard(action) if endswith(action, ":*")
is_service_wildcard(action) if action == "*"