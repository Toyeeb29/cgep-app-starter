# policies/gap02_dynamodb_cmk.rego
# METADATA
# title: GAP-02 - DynamoDB PHI table must use customer CMK
# description: "Every aws_dynamodb_table holding PHI must have server_side_encryption enabled with a customer-managed KMS key, not the AWS-owned default."
# custom:
#   gap_id: GAP-02
#   hipaa: 164.312(a)(2)(iv)
#   control_id: SC-28
#   severity: critical
package capstone.gap02

import rego.v1

deny contains msg if {
	some r in input.planned_values.root_module.resources
	r.type == "aws_dynamodb_table"
	not has_cmk_sse(r)
	msg := sprintf(
		"[GAP-02][HIPAA 164.312(a)(2)(iv)] %s: DynamoDB table uses AWS-owned default key, not a customer CMK. Remediation: add server_side_encryption block with enabled=true and kms_key_arn.",
		[r.address],
	)
}

has_cmk_sse(r) if {
	some sse in r.values.server_side_encryption
	sse.enabled == true
	kms_arn_referenced
}

# kms_key_arn is "known after apply" at plan time; check the configuration wiring
kms_arn_referenced if {
	some cr in input.configuration.root_module.resources
	cr.type == "aws_dynamodb_table"
	some ref in cr.expressions.server_side_encryption[0].kms_key_arn.references
	contains(ref, "aws_kms_key")
}