######################################################################
# Acme Health — Patient Intake API (CGE-P Capstone Starter)
#
# This is the workload your capstone repo wraps with GRC controls.
# It is INTENTIONALLY non-compliant. See GAPS.md for the named flaws
# your Rego policies + Terraform overrides are expected to remediate.
######################################################################

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws     = { source = "hashicorp/aws", version = "~> 5.0" }
    random  = { source = "hashicorp/random", version = "~> 3.6" }
    archive = { source = "hashicorp/archive", version = "~> 2.4" }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = "acme-health-intake"
      ManagedBy = "terraform"
      Workload  = "patient-intake-api"
      DataClass = "phi"
    }
  }
}

resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  name_prefix = "acme-health-intake"
  suffix      = random_id.suffix.hex
}

######################################################################
# Networking — VPC the learner is expected to put the Lambda inside.
# Two public + two private subnets across two AZs.
######################################################################

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "main" {
  cidr_block           = "10.42.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "${local.name_prefix}-vpc" }
}

resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.42.${count.index}.0/24"
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = { Name = "${local.name_prefix}-public-${count.index}" }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.42.${count.index + 10}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = { Name = "${local.name_prefix}-private-${count.index}" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = { Name = "${local.name_prefix}-igw" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = { Name = "${local.name_prefix}-public-rt" }
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

######################################################################
# DynamoDB — submissions table.
# GAP-02: encryption uses AWS-owned default, not a CMK you control.
######################################################################

resource "aws_dynamodb_table" "intake" {
  name         = "${local.name_prefix}-submissions-${local.suffix}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "submission_id"

  attribute {
    name = "submission_id"
    type = "S"
  }

  # No server_side_encryption block. Defaults to AWS-owned key.
  # GAP-02: capstone learner expected to add this with a customer-owned key.
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.cmk.arn
  }
}

######################################################################
# S3 — uploads bucket.
# GAP-01: relies on AWS-managed SSE-S3 (default since 2023) instead of
#         SSE-KMS with a customer CMK. PHI keys are not under customer
#         custody.
# GAP-03: no bucket policy denying non-TLS requests
#         (aws:SecureTransport).
# GAP-04: no versioning. PHI overwrites are unrecoverable.
#
# Note: AWS now defaults new buckets to SSE-S3 + full public access block.
# The "gaps" here are real residual gaps once those defaults are in place.
######################################################################

resource "aws_s3_bucket" "uploads" {
  bucket = "${local.name_prefix}-uploads-${local.suffix}"
}

# --- MITIGATION GAP-01: Cifrado con nuestra propia llave KMS ---
resource "aws_s3_bucket_server_side_encryption_configuration" "uploads_encryption" {
  bucket = aws_s3_bucket.uploads.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.cmk.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

# --- MITIGACIÓN GAP-04: Versionado para asegurar disponibilidad de datos médicos ---
resource "aws_s3_bucket_versioning" "uploads_versioning" {
  bucket = aws_s3_bucket.uploads.id
  versioning_configuration {
    status = "Enabled"
  }
}

# --- MITIGACIÓN GAP-03: Política para denegar accesos que no usen HTTPS/TLS ---
resource "aws_s3_bucket_policy" "uploads_tls_policy" {
  bucket = aws_s3_bucket.uploads.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceTLSRequestsOnly"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.uploads.arn,
          "${aws_s3_bucket.uploads.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false" # Si no es HTTPS, se bloquea por completo
          }
        }
      }
    ]
  })
}

# (Intentionally omitted: SSE-KMS encryption with a customer CMK,
#  bucket policy enforcing aws:SecureTransport, versioning, lifecycle.
#  These are the gaps the learner closes.)

######################################################################
# Lambda — the intake handler.
# GAP-05: not deployed inside the VPC.
# GAP-06: no reserved concurrency, no DLQ, no X-Ray.
# GAP-07: IAM role has dynamodb:* and s3:* on the resources (over-broad).
######################################################################

data "archive_file" "handler" {
  type        = "zip"
  source_file = "${path.module}/lambda/handler.py"
  output_path = "${path.module}/lambda/handler.zip"
}

resource "aws_iam_role" "lambda" {
  name = "${local.name_prefix}-lambda-${local.suffix}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# --- MITIGACIÓN GAP-07: Reducción al Principio de Menor Privilegio ---
resource "aws_iam_role_policy" "lambda_inline" {
  name = "intake-data-access"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DynamoDBGranularWrite"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem" # Solo permite insertar datos, no borrar ni leer la tabla completa
        ]
        Resource = aws_dynamodb_table.intake.arn
      },
      {
        Sid    = "S3GranularPut"
        Effect = "Allow"
        Action = [
          "s3:PutObject",          # Permitir subir los archivos médicos
          "s3:PutObjectAcl"        # Requerido a veces para asignación de control de acceso
        ]
        Resource = "${aws_s3_bucket.uploads.arn}/*"
      },
      {
        Sid    = "KMSKeyUsage"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey" # Requerido para que la Lambda pueda escribir en recursos cifrados con nuestra CMK
        ]
        Resource = aws_kms_key.cmk.arn
      }
    ]
  })
}

resource "aws_lambda_function" "intake" {
  function_name    = "${local.name_prefix}-handler-${local.suffix}"
  role             = aws_iam_role.lambda.arn
  handler          = "handler.handler"
  runtime          = "python3.12"
  filename         = data.archive_file.handler.output_path
  source_code_hash = data.archive_file.handler.output_base64sha256
  timeout          = 10

  environment {
    variables = {
      INTAKE_TABLE  = aws_dynamodb_table.intake.name
      UPLOAD_BUCKET = aws_s3_bucket.uploads.id
    }
  }

  # GAP-05: no vpc_config block. Learner expected to add one referencing
  # aws_subnet.private[*] and a hardened security group.
}

######################################################################
# API Gateway — HTTP API in front of the Lambda.
# GAP-08: no access logging, no throttling, no WAF.
######################################################################

resource "aws_apigatewayv2_api" "intake" {
  name          = "${local.name_prefix}-api-${local.suffix}"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_integration" "lambda" {
  api_id                 = aws_apigatewayv2_api.intake.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.intake.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "intake" {
  api_id    = aws_apigatewayv2_api.intake.id
  route_key = "POST /intake"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.intake.id
  name        = "$default"
  auto_deploy = true
  # GAP-08: no access_log_settings. Learner expected to wire CloudWatch logs.
}

resource "aws_lambda_permission" "apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.intake.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.intake.execution_arn}/*/*"
}

resource "aws_kms_key" "cmk" {
  description             = "KMS CMK for Acme Health Patient Intake API (SOC 2 CC6.1 Compliance)"
  deletion_window_in_days = 7
  enable_key_rotation     = true # Requerimiento estricto de auditoría

  tags = {
    Environment = "sandbox"
    ManagedBy   = "Terraform"
    Compliance  = "SOC2-CC6.1"
  }
}

resource "aws_kms_alias" "cmk_alias" {
  name          = "alias/acme-health-cmk"
  target_key_id = aws_kms_key.cmk.key_id
}

# --- CAJA FUERTE DE EVIDENCIAS DE AUDITORÍA INMUTABLES ---

resource "aws_s3_bucket" "evidence_vault" {
  bucket        = "acme-health-evidence-vault-520999258289" # Tu número de cuenta para que sea único
  force_destroy = true

  # Activamos Object Lock a nivel de infraestructura
  object_lock_enabled = true
}

resource "aws_s3_bucket_object_lock_configuration" "vault_lock" {
  bucket = aws_s3_bucket.evidence_vault.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = 90 # Las evidencias quedan blindadas por 90 días
    }
  }
}
