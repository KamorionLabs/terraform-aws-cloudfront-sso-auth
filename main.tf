# -----------------------------------------------------------------------------
# CloudFront SSO Authentication Module
# Uses AWS Identity Center (SAML) + Lambda@Edge to protect CloudFront distributions
# -----------------------------------------------------------------------------

locals {
  name_prefix = var.name_prefix != "" ? var.name_prefix : var.name

  # Lambda function names
  lambda_protect_name  = "${local.name_prefix}-sso-protect"
  lambda_acs_name      = "${local.name_prefix}-sso-acs"
  lambda_metadata_name = "${local.name_prefix}-sso-metadata"

  # SAML paths
  saml_acs_path      = "/saml/acs"
  saml_metadata_path = "/saml/metadata.xml"
}

# -----------------------------------------------------------------------------
# Secrets Manager - Store SAML configuration
# -----------------------------------------------------------------------------
resource "aws_secretsmanager_secret" "saml_config" {
  provider = aws.us_east_1

  name        = "${local.name_prefix}-saml-config"
  description = "SAML configuration for CloudFront SSO authentication"

  tags = var.tags
}

resource "aws_secretsmanager_secret_version" "saml_config" {
  provider = aws.us_east_1

  secret_id = aws_secretsmanager_secret.saml_config.id
  secret_string = jsonencode({
    audience     = var.saml_audience
    init_vector  = random_password.init_vector.result
    private_key  = random_password.private_key.result
    idp_metadata = var.idp_metadata
  })

  lifecycle {
    ignore_changes = [secret_string]
  }
}

resource "random_password" "init_vector" {
  length  = 16
  special = false
}

resource "random_password" "private_key" {
  length  = 32
  special = false
}

# -----------------------------------------------------------------------------
# IAM Role for Lambda@Edge
# -----------------------------------------------------------------------------
resource "aws_iam_role" "lambda_edge" {
  name = "${local.name_prefix}-lambda-edge-sso"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = [
            "lambda.amazonaws.com",
            "edgelambda.amazonaws.com"
          ]
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "lambda_edge" {
  name = "${local.name_prefix}-lambda-edge-sso-policy"
  role = aws_iam_role.lambda_edge.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

# -----------------------------------------------------------------------------
# Lambda@Edge Functions
# -----------------------------------------------------------------------------

# Build Lambda package
data "archive_file" "lambda_package" {
  type        = "zip"
  source_dir  = "${path.module}/lambda/dist"
  output_path = "${path.module}/lambda/package.zip"

  depends_on = [null_resource.build_lambda]
}

resource "null_resource" "build_lambda" {
  triggers = {
    source_hash = sha256(join("", [
      file("${path.module}/lambda/src/handlers/protect.ts"),
      file("${path.module}/lambda/src/handlers/acs.ts"),
      file("${path.module}/lambda/src/handlers/metadata.ts"),
      file("${path.module}/lambda/src/shared/config.ts"),
      file("${path.module}/lambda/src/shared/utils/crypt.ts"),
      file("${path.module}/lambda/src/shared/utils/cloudfront.ts"),
      file("${path.module}/lambda/package.json"),
    ]))
    secrets_version = aws_secretsmanager_secret_version.saml_config.version_id
  }

  provisioner "local-exec" {
    command     = "npm ci && npm run build"
    working_dir = "${path.module}/lambda"

    environment = {
      SAML_AUDIENCE     = var.saml_audience
      SAML_INIT_VECTOR  = random_password.init_vector.result
      SAML_PRIVATE_KEY  = random_password.private_key.result
      SAML_IDP_METADATA = var.idp_metadata
    }
  }
}

# Protect Lambda - validates cookies on each request
resource "aws_lambda_function" "protect" {
  provider = aws.us_east_1

  function_name = local.lambda_protect_name
  description   = "Lambda@Edge - Validate SSO authentication cookie"
  role          = aws_iam_role.lambda_edge.arn
  handler       = "handlers/protect.handler"
  runtime       = "nodejs20.x"
  timeout       = 5
  memory_size   = 128

  filename         = data.archive_file.lambda_package.output_path
  source_code_hash = data.archive_file.lambda_package.output_base64sha256

  publish = true

  tags = var.tags
}

# ACS Lambda - handles SAML assertion callback
resource "aws_lambda_function" "acs" {
  provider = aws.us_east_1

  function_name = local.lambda_acs_name
  description   = "Lambda@Edge - Handle SAML Assertion Consumer Service"
  role          = aws_iam_role.lambda_edge.arn
  handler       = "handlers/acs.handler"
  runtime       = "nodejs20.x"
  timeout       = 5
  memory_size   = 128

  filename         = data.archive_file.lambda_package.output_path
  source_code_hash = data.archive_file.lambda_package.output_base64sha256

  publish = true

  tags = var.tags
}

# Metadata Lambda - returns SP metadata.xml
resource "aws_lambda_function" "metadata" {
  provider = aws.us_east_1

  function_name = local.lambda_metadata_name
  description   = "Lambda@Edge - Return SAML Service Provider metadata"
  role          = aws_iam_role.lambda_edge.arn
  handler       = "handlers/metadata.handler"
  runtime       = "nodejs20.x"
  timeout       = 5
  memory_size   = 128

  filename         = data.archive_file.lambda_package.output_path
  source_code_hash = data.archive_file.lambda_package.output_base64sha256

  publish = true

  tags = var.tags
}

# -----------------------------------------------------------------------------
# CloudWatch Log Groups (Lambda@Edge logs appear in edge regions)
# -----------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "protect" {
  provider = aws.us_east_1

  name              = "/aws/lambda/us-east-1.${local.lambda_protect_name}"
  retention_in_days = var.log_retention_days

  tags = var.tags
}

resource "aws_cloudwatch_log_group" "acs" {
  provider = aws.us_east_1

  name              = "/aws/lambda/us-east-1.${local.lambda_acs_name}"
  retention_in_days = var.log_retention_days

  tags = var.tags
}

resource "aws_cloudwatch_log_group" "metadata" {
  provider = aws.us_east_1

  name              = "/aws/lambda/us-east-1.${local.lambda_metadata_name}"
  retention_in_days = var.log_retention_days

  tags = var.tags
}
