# policies/tests/gap02_test.rego
package capstone.gap02_test

import rego.v1
import data.capstone.gap02

compliant_input := {
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_dynamodb_table.intake",
		"type": "aws_dynamodb_table",
		"values": {"server_side_encryption": [{"enabled": true}]},
	}]}},
	"configuration": {"root_module": {"resources": [{
		"type": "aws_dynamodb_table",
		"name": "intake",
		"expressions": {"server_side_encryption": [{"kms_key_arn": {"references": ["aws_kms_key.phi.arn", "aws_kms_key.phi"]}}]},
	}]}},
}

noncompliant_input := {
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_dynamodb_table.intake",
		"type": "aws_dynamodb_table",
		"values": {},
	}]}},
	"configuration": {"root_module": {"resources": [{
		"type": "aws_dynamodb_table",
		"name": "intake",
	}]}},
}

test_compliant_passes if {
	count(gap02.deny) == 0 with input as compliant_input
}

test_noncompliant_fails if {
	some msg in gap02.deny with input as noncompliant_input
	contains(msg, "GAP-02")
}