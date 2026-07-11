# policies/tests/gap07_test.rego
package capstone.gap07_test

import rego.v1
import data.capstone.gap07

compliant_input := {"planned_values": {"root_module": {"resources": [{
	"address": "aws_iam_role_policy.lambda_inline",
	"type": "aws_iam_role_policy",
	"values": {"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"dynamodb:PutItem\"],\"Resource\":\"arn:aws:dynamodb:us-east-1:111:table/x\"}]}"},
}]}}}

noncompliant_input := {"planned_values": {"root_module": {"resources": [{
	"address": "aws_iam_role_policy.lambda_inline",
	"type": "aws_iam_role_policy",
	"values": {"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:*\",\"Resource\":\"*\"}]}"},
}]}}}

test_compliant_passes if {
	count(gap07.deny) == 0 with input as compliant_input
}

test_noncompliant_fails if {
	some msg in gap07.deny with input as noncompliant_input
	contains(msg, "GAP-07")
	contains(msg, "s3:*")
}