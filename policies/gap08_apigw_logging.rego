# policies/gap08_apigw_logging.rego
# METADATA
# title: GAP-08 - API Gateway stage must have access logging
# description: "Every API Gateway stage fronting PHI must have access logging enabled. Without it there is no audit trail of who touched patient data."
# custom:
#   gap_id: GAP-08
#   hipaa: 164.312(b)
#   control_id: AU-2
#   severity: high
package capstone.gap08

import rego.v1

deny contains msg if {
	some r in input.planned_values.root_module.resources
	r.type == "aws_apigatewayv2_stage"
	not has_access_logging(r)
	msg := sprintf(
		"[GAP-08][HIPAA 164.312(b)] %s: no access logging. There is no audit record of PHI access through the API. Remediation: add access_log_settings with a CloudWatch log group destination.",
		[r.address],
	)
}

has_access_logging(r) if {
	count(r.values.access_log_settings) > 0
	log_destination_referenced
}

# destination_arn is "known after apply"; check configuration wiring
log_destination_referenced if {
	some cr in input.configuration.root_module.resources
	cr.type == "aws_apigatewayv2_stage"
	some ref in cr.expressions.access_log_settings[0].destination_arn.references
	contains(ref, "aws_cloudwatch_log_group")
}