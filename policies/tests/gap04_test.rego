# policies/tests/gap04_test.rego
package capstone.gap04_test

import rego.v1
import data.capstone.gap04

compliant_input := {
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_s3_bucket_versioning.uploads",
		"type": "aws_s3_bucket_versioning",
		"values": {"versioning_configuration": [{"status": "Enabled"}]},
	}]}},
	"configuration": {"root_module": {"resources": [
		{
			"type": "aws_s3_bucket",
			"name": "uploads",
		},
		{
			"type": "aws_s3_bucket_versioning",
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
	count(gap04.deny) == 0 with input as compliant_input
}

test_noncompliant_fails if {
	some msg in gap04.deny with input as noncompliant_input
	contains(msg, "GAP-04")
}