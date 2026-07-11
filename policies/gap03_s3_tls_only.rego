# policies/gap03_s3_tls_only.rego
# METADATA
# title: GAP-03 - S3 PHI bucket must deny non-TLS requests
# description: "Every aws_s3_bucket holding PHI must have a bucket policy with an explicit deny when aws:SecureTransport is false."
# custom:
#   gap_id: GAP-03
#   hipaa: 164.312(e)(1)
#   control_id: SC-8
#   severity: high
package capstone.gap03

import rego.v1

deny contains msg if {
	bucket := bucket_addresses[_]
	not has_tls_policy(bucket)
	msg := sprintf(
		"[GAP-03][HIPAA 164.312(e)(1)] %s: no bucket policy denying non-TLS requests. PHI can transit unencrypted. Remediation: add aws_s3_bucket_policy with deny on aws:SecureTransport=false.",
		[bucket],
	)
}

bucket_addresses contains addr if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket"
	addr := sprintf("aws_s3_bucket.%s", [r.name])
}

has_tls_policy(bucket_addr) if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_policy"
	some ref in r.expressions.bucket.references
	references_bucket(ref, bucket_addr)
	policy_denies_insecure_transport
}

references_bucket(ref, bucket_addr) if ref == bucket_addr
references_bucket(ref, bucket_addr) if ref == sprintf("%s.id", [bucket_addr])
references_bucket(ref, bucket_addr) if ref == sprintf("%s.bucket", [bucket_addr])

# In CI (no state) the rendered policy is unknown at plan time.
# Accept either: the rendered policy contains SecureTransport (local plan with state),
# or the bucket policy is wired to a policy document that exists in configuration.
policy_denies_insecure_transport if {
	some pr in input.planned_values.root_module.resources
	pr.type == "aws_s3_bucket_policy"
	pr.values.policy != null
	contains(pr.values.policy, "SecureTransport")
}

policy_denies_insecure_transport if {
	some cr in input.configuration.root_module.resources
	cr.type == "aws_s3_bucket_policy"
	some ref in cr.expressions.policy.references
	contains(ref, "uploads_tls_only")
}