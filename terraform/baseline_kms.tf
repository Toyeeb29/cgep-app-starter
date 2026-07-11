# baseline_kms.tf
# Customer-managed CMK for PHI at rest (GAP-01, GAP-02)
# HIPAA 164.312(a)(2)(iv): encryption keys under customer custody

resource "aws_kms_key" "phi" {
  description             = "CMK for PHI at rest (S3 uploads + DynamoDB intake)"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

resource "aws_kms_alias" "phi" {
  name          = "alias/${local.name_prefix}-phi-${local.suffix}"
  target_key_id = aws_kms_key.phi.key_id
}