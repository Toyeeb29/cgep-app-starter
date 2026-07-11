# dynamodb_override.tf
# GAP-02: DynamoDB PHI table must use customer CMK — HIPAA 164.312(a)(2)(iv)
# Terraform override file: merges with the starter's aws_dynamodb_table.intake

resource "aws_dynamodb_table" "intake" {
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.phi.arn
  }
}