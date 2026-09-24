# -----------------------------------------------------------------------------
# CloudFront SSO Authentication Module
# Uses AWS Identity Center (SAML), a CloudFront Function (session check) and
# Lambda@Edge (SAML flow) to protect CloudFront distributions
# -----------------------------------------------------------------------------

locals {
  name_prefix = var.name_prefix != "" ? var.name_prefix : var.name

  # Lambda function names
  lambda_protect_name  = "${local.name_prefix}-sso-protect"
  lambda_acs_name      = "${local.name_prefix}-sso-acs"
  lambda_metadata_name = "${local.name_prefix}-sso-metadata"
  lambda_login_name    = "${local.name_prefix}-sso-login"
  sso_check_name       = "${local.name_prefix}-sso-check"

  # SAML paths
  saml_acs_path      = "/saml/acs"
  saml_metadata_path = "/saml/metadata.xml"
  saml_login_path    = "/saml/login"
  saml_logout_path   = "/saml/logout"
  cookie_name        = "sso_auth"

  # The sso-check library, full-line comments blanked and indentation stripped
  # (lines kept, so deployed line numbers match the source) to stay far under
  # the 10 KB CloudFront Functions limit once composed with another function.
  # Every sentinel is replaced together with its fail-closed fallback.
  sso_check_library_js = replace(replace(replace(replace(replace(
    join("\n", [
      for line in split("\n", file("${path.module}/functions/sso-check.js")) :
      can(regex("^\\s*//", line)) ? "" : trimspace(line)
    ]),
    "/*__SSO_HMAC_KEY__*/''", jsonencode(random_password.hmac_key.result)),
    "/*__SSO_AUDIENCE__*/''", jsonencode(var.saml_audience)),
    "/*__SSO_COOKIE_NAME__*/'sso_auth'", jsonencode(local.cookie_name)),
    "/*__SSO_LOGIN_PATH__*/'/saml/login'", jsonencode(local.saml_login_path)),
    "/*__SSO_LOGOUT_PATH__*/'/saml/logout'", jsonencode(local.saml_logout_path)
  )

  sso_check_import_js = "import crypto from 'crypto';"

  sso_check_function_code = join("\n", [
    local.sso_check_import_js,
    local.sso_check_library_js,
    "function handler(event) {",
    "    return ssoCheck(event) || event.request;",
    "}",
    "",
  ])
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
    audience            = var.saml_audience
    hmac_key            = random_password.hmac_key.result
    idp_metadata        = var.idp_metadata
    signing_cert        = tls_self_signed_cert.saml_signing.cert_pem
    signing_private_key = tls_private_key.saml_signing.private_key_pem
  })

  lifecycle {
    ignore_changes = [secret_string]
  }
}

# Signs the session cookie. Shared by the ACS Lambda (signs) and the sso-check
# CloudFront Function (verifies). Replacing it signs everyone out once.
resource "random_password" "hmac_key" {
  length  = 64
  special = false
}

# -----------------------------------------------------------------------------
# TLS Certificate for SAML Request Signing
# -----------------------------------------------------------------------------
resource "tls_private_key" "saml_signing" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "saml_signing" {
  private_key_pem = tls_private_key.saml_signing.private_key_pem

  subject {
    common_name  = "SAML SP Signing Certificate"
    organization = var.name
  }

  validity_period_hours = 87600 # 10 years

  allowed_uses = [
    "digital_signature",
  ]
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

# Write SAML config to a JSON file for the build script
# This ensures config is available even when building manually
resource "local_file" "saml_config" {
  filename = "${path.module}/lambda/.saml-config.json"
  content = jsonencode({
    audience               = var.saml_audience
    hmacKey                = random_password.hmac_key.result
    idpMetadata            = var.idp_metadata
    signingCert            = tls_self_signed_cert.saml_signing.cert_pem
    signingPrivateKey      = tls_private_key.saml_signing.private_key_pem
    signAuthnRequests      = var.sign_authn_requests ? "true" : "false"
    sessionDurationSeconds = tostring(var.session_duration_hours * 3600)
    bypassHeaders          = jsonencode(var.bypass_headers)
  })
  file_permission = "0600"
}

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
      file("${path.module}/lambda/src/handlers/login.ts"),
      file("${path.module}/lambda/src/shared/config.ts"),
      file("${path.module}/lambda/src/shared/utils/token.ts"),
      file("${path.module}/lambda/src/shared/utils/cloudfront.ts"),
      file("${path.module}/lambda/src/shared/utils/bypass.ts"),
      file("${path.module}/lambda/package.json"),
    ]))
    secrets_version = aws_secretsmanager_secret_version.saml_config.version_id
    config_hash     = local_file.saml_config.content_md5
  }

  depends_on = [local_file.saml_config]

  provisioner "local-exec" {
    command     = "npm ci && npm run build"
    working_dir = "${path.module}/lambda"
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

# Login Lambda - starts the SAML flow for the sso-check CloudFront Function
resource "aws_lambda_function" "login" {
  provider = aws.us_east_1

  function_name = local.lambda_login_name
  description   = "Lambda@Edge - Start the SAML login flow"
  role          = aws_iam_role.lambda_edge.arn
  handler       = "handlers/login.handler"
  runtime       = "nodejs20.x"
  timeout       = 5
  memory_size   = 128

  filename         = data.archive_file.lambda_package.output_path
  source_code_hash = data.archive_file.lambda_package.output_base64sha256

  publish = true

  tags = var.tags
}

# -----------------------------------------------------------------------------
# CloudFront Function - session check on every protected behavior
# -----------------------------------------------------------------------------

# Verifies the signed session cookie at viewer-request, in every edge location.
# Unlike the protect Lambda@Edge, it can share a cache behavior with other
# CloudFront Functions (AWS forbids mixing both kinds in viewer events).
resource "aws_cloudfront_function" "sso_check" {
  name    = local.sso_check_name
  runtime = "cloudfront-js-2.0"
  comment = "SSO session check (signed cookie), redirects to ${local.saml_login_path}"
  publish = true
  code    = local.sso_check_function_code
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

resource "aws_cloudwatch_log_group" "login" {
  provider = aws.us_east_1

  name              = "/aws/lambda/us-east-1.${local.lambda_login_name}"
  retention_in_days = var.log_retention_days

  tags = var.tags
}
