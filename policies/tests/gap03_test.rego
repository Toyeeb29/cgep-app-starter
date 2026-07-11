# policies/tests/gap03_test.rego
package capstone.gap03_test

import rego.v1
import data.capstone.gap03

compliant_input := {
	"planned_values": {"root_module": {"resources": []}},
	"configuration": {"root_module": {"resources": [
		{
			"type": "aws_s3_bucket",
			"name": "uploads",
		},
		{
			"type": "aws_s3_bucket_policy",
			"name": "uploads_tls_only",
			"expressions": {
				"bucket": {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]},
				"policy": {"references": ["data.aws_iam_policy_document.uploads_tls_only.json", "data.aws_iam_policy_document.uploads_tls_only"]},
			},
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
	count(gap03.deny) == 0 with input as compliant_input
}

test_noncompliant_fails if {
	some msg in gap03.deny with input as noncompliant_input
	contains(msg, "GAP-03")
}