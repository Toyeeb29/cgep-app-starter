# policies/tests/gap08_test.rego
package capstone.gap08_test

import rego.v1
import data.capstone.gap08

compliant_input := {
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_apigatewayv2_stage.default",
		"type": "aws_apigatewayv2_stage",
		"values": {"access_log_settings": [{"format": "{}"}]},
	}]}},
	"configuration": {"root_module": {"resources": [{
		"type": "aws_apigatewayv2_stage",
		"name": "default",
		"expressions": {"access_log_settings": [{"destination_arn": {"references": ["aws_cloudwatch_log_group.apigw_access.arn", "aws_cloudwatch_log_group.apigw_access"]}}]},
	}]}},
}

noncompliant_input := {
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_apigatewayv2_stage.default",
		"type": "aws_apigatewayv2_stage",
		"values": {"access_log_settings": []},
	}]}},
	"configuration": {"root_module": {"resources": [{
		"type": "aws_apigatewayv2_stage",
		"name": "default",
	}]}},
}

test_compliant_passes if {
	count(gap08.deny) == 0 with input as compliant_input
}

test_noncompliant_fails if {
	some msg in gap08.deny with input as noncompliant_input
	contains(msg, "GAP-08")
}