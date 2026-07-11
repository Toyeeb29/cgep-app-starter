# policies/tests/gap01_test.rego
package capstone.gap01_test

import rego.v1
import data.capstone.gap01

compliant_input := {
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
		"type": "aws_s3_bucket_server_side_encryption_configuration",
		"values": {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}]},
	}]}},
	"configuration": {"root_module": {"resources": [
		{
			"type": "aws_s3_bucket",
			"name": "uploads",
		},
		{
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"name": "uploads",
			"expressions": {"bucket": {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]}},
		},
	]}},
}

noncompliant_input := {
	"planned_values": {"root_module": {"resources": []}},
	"configuration": {"root_module": {"resources": [{
		"type": "aws_s3_bucket",
		"name": "uploads",
	}]}},
}

test_compliant_passes if {
	count(gap01.deny) == 0 with input as compliant_input
}

test_noncompliant_fails if {
	some msg in gap01.deny with input as noncompliant_input
	contains(msg, "GAP-01")
	contains(msg, "aws_s3_bucket.uploads")
}