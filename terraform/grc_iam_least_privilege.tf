# GAP-07 fixed: the Lambda may only do what handler.py actually does
# HIPAA 164.312(a)(1) Access control (least privilege)

data "aws_iam_policy_document" "lambda_data_access" {
  statement {
    sid       = "WriteSubmissions"
    effect    = "Allow"
    actions   = ["dynamodb:PutItem"]
    resources = [aws_dynamodb_table.intake.arn]
  }

  statement {
    sid       = "WriteUploads"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.uploads.arn}/uploads/*"]
  }

  statement {
    sid       = "UsePhiKey"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [aws_kms_key.phi.arn]
  }
}

resource "aws_iam_role_policy" "lambda_inline" {
  name   = "intake-data-access"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda_data_access.json
}
