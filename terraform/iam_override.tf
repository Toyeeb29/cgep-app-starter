# iam_override.tf
# GAP-07: least-privilege IAM — HIPAA 164.312(a)(1)
# Override replaces the starter's wildcard policy (dynamodb:*, s3:*)
# with only the actions the intake handler actually performs.

resource "aws_iam_role_policy" "lambda_inline" {
  name = "intake-data-access"
  role = aws_iam_role.lambda.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DynamoWriteIntake"
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem"]
        Resource = aws_dynamodb_table.intake.arn
      },
      {
        Sid      = "S3WriteUploads"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${aws_s3_bucket.uploads.arn}/*"
      },
      {
        Sid      = "KmsForPhiCmk"
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource = aws_kms_key.phi.arn
      }
    ]
  })
}