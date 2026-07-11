# policies/gap04_s3_versioning.rego
# METADATA
# title: GAP-04 - S3 PHI bucket must have versioning enabled
# description: "Every aws_s3_bucket holding PHI must have versioning so overwrites and deletions are recoverable."
# custom:
#   gap_id: GAP-04
#   hipaa: 164.308(a)(7)
#   control_id: CP-9
#   severity: high
package capstone.gap04

import rego.v1

deny contains msg if {
	bucket := bucket_addresses[_]
	not has_versioning(bucket)
	msg := sprintf(
		"[GAP-04][HIPAA 164.308(a)(7)] %s: no versioning. PHI overwrites are unrecoverable, violating contingency-plan requirements. Remediation: add aws_s3_bucket_versioning with status=Enabled.",
		[bucket],
	)
}

bucket_addresses contains addr if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket"
	addr := sprintf("aws_s3_bucket.%s", [r.name])
}

has_versioning(bucket_addr) if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_versioning"
	some ref in r.expressions.bucket.references
	references_bucket(ref, bucket_addr)
	versioning_enabled
}

references_bucket(ref, bucket_addr) if ref == bucket_addr
references_bucket(ref, bucket_addr) if ref == sprintf("%s.id", [bucket_addr])
references_bucket(ref, bucket_addr) if ref == sprintf("%s.bucket", [bucket_addr])

versioning_enabled if {
	some pr in input.planned_values.root_module.resources
	pr.type == "aws_s3_bucket_versioning"
	some vc in pr.values.versioning_configuration
	vc.status == "Enabled"
}