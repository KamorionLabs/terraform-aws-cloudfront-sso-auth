# -----------------------------------------------------------------------------
# CloudFront SSO Authentication Module
# Uses AWS Identity Center (SAML), a CloudFront Function (session check) and
# Lambda@Edge (SAML flow) to protect CloudFront distributions
# -----------------------------------------------------------------------------

locals {
  name_prefix = var.name_prefix != "" ? var.name_prefix : var.name

  # Per-instance build directory: instances of the module share path.module,
  # so a common lambda/ build would mix their configurations and race.
  build_dir = "${path.module}/lambda/${local.build_subdir}"
  # Relative to lambda/, the working directory of the build command
  build_subdir = ".build/${local.name_prefix}"

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
  cookie_name        = var.cookie_name

  # ACS URLs declared in the SP metadata: the auth host alone in shared session
  # mode, one per CloudFront domain otherwise.
  acs_domains = var.auth_host != "" ? [var.auth_host] : var.cloudfront_domains

  # The sso-check library, full-line comments blanked and indentation stripped
  # (lines kept, so deployed line numbers match the source) to stay far under
  # the 10 KB CloudFront Functions limit once composed with another function.
  # Every sentinel is replaced together with its fail-closed fallback.
  sso_check_library_js = replace(replace(replace(replace(replace(replace(
    join("\n", [
      for line in split("\n", file("${path.module}/functions/sso-check.js")) :
      can(regex("^\\s*//", line)) ? "" : trimspace(line)
    ]),
    "/*__SSO_HMAC_KEY__*/''", jsonencode(random_password.hmac_key.result)),
    "/*__SSO_AUDIENCE__*/''", jsonencode(var.saml_audience)),
    "/*__SSO_COOKIE_NAME__*/'sso_auth'", jsonencode(local.cookie_name)),
    "/*__SSO_LOGIN_PATH__*/'/saml/login'", jsonencode(local.saml_login_path)),
    "/*__SSO_LOGOUT_PATH__*/'/saml/logout'", jsonencode(local.saml_logout_path)),
    "/*__SSO_COOKIE_DOMAIN__*/''", jsonencode(var.cookie_domain)
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

locals {
  name_id_format_urn = {
    transient    = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
    persistent   = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
    emailAddress = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    unspecified  = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
  }[var.name_id_format]
}

# The SAML configuration baked into the Lambda code at build time
# (Lambda@Edge has no environment variables).
locals {
  saml_build_env = {
    SAML_AUDIENCE                 = var.saml_audience
    SAML_HMAC_KEY                 = random_password.hmac_key.result
    SAML_IDP_METADATA             = var.idp_metadata
    SAML_SIGNING_CERT             = tls_self_signed_cert.saml_signing.cert_pem
    SAML_SIGNING_PRIVATE_KEY      = tls_private_key.saml_signing.private_key_pem
    SAML_SIGN_AUTHN_REQUESTS      = var.sign_authn_requests ? "true" : "false"
    SAML_SESSION_DURATION_SECONDS = tostring(var.session_duration_hours * 3600)
    SAML_BYPASS_HEADERS           = jsonencode(var.bypass_headers)
    SAML_COOKIE_DOMAIN            = var.cookie_domain
    SAML_COOKIE_NAME              = local.cookie_name
    SAML_AUTH_HOST                = var.auth_host
    SAML_NAME_ID_FORMAT           = local.name_id_format_urn
  }

  # Hash of the build inputs, known at plan time: the sources and the baked-in
  # configuration. It stands for the package, which only exists after a build,
  # so a fresh checkout (CI) plans no change as long as the inputs are the same.
  lambda_source_hash = sha256(join("", [
    for file in sort(setunion(
      fileset("${path.module}/lambda", "src/**/*.ts"),
      fileset("${path.module}/lambda", "scripts/*.js"),
      ["package.json", "package-lock.json", "tsconfig.json"],
    )) : filesha256("${path.module}/lambda/${file}")
  ]))
  lambda_config_hash = nonsensitive(sha256(jsonencode(local.saml_build_env)))
  lambda_code_hash   = base64sha256("${local.lambda_source_hash}:${local.lambda_config_hash}")

  lambda_package = "${local.build_dir}/package.zip"
}

# Builds and zips the package when its inputs change, before the Lambda
# functions upload it. The configuration goes through the environment, never
# to a file.
resource "null_resource" "build_lambda" {
  triggers = {
    code_hash = local.lambda_code_hash
    build_dir = local.build_dir
  }

  provisioner "local-exec" {
    command     = "mkdir -p '${local.build_subdir}' && rm -rf '${local.build_subdir}/src' '${local.build_subdir}/scripts' '${local.build_subdir}/dist' '${local.build_subdir}/.saml-config.json' '${local.build_subdir}/package.zip' && cp -R src scripts package.json package-lock.json tsconfig.json '${local.build_subdir}/' && cd '${local.build_subdir}' && npm ci && npm run build && python3 -c \"import shutil; shutil.make_archive('package', 'zip', 'dist')\""
    working_dir = "${path.module}/lambda"
    environment = local.saml_build_env
  }
}

# Protect Lambda - validates cookies on each request
resource "aws_lambda_function" "protect" {
  provider = aws.us_east_1

  function_name = local.lambda_protect_name
  description   = "Lambda@Edge - Validate SSO authentication cookie"
  role          = aws_iam_role.lambda_edge.arn
  handler       = "handlers/protect.handler"
  runtime       = "nodejs22.x"
  timeout       = 5
  memory_size   = var.lambda_memory_size.protect

  filename         = local.lambda_package
  source_code_hash = local.lambda_code_hash

  publish = true

  tags = var.tags

  depends_on = [null_resource.build_lambda]
}

# ACS Lambda - handles SAML assertion callback
resource "aws_lambda_function" "acs" {
  provider = aws.us_east_1

  function_name = local.lambda_acs_name
  description   = "Lambda@Edge - Handle SAML Assertion Consumer Service"
  role          = aws_iam_role.lambda_edge.arn
  handler       = "handlers/acs.handler"
  runtime       = "nodejs22.x"
  timeout       = 5
  memory_size   = var.lambda_memory_size.acs

  filename         = local.lambda_package
  source_code_hash = local.lambda_code_hash

  publish = true

  tags = var.tags

  depends_on = [null_resource.build_lambda]
}

# Metadata Lambda - returns SP metadata.xml
resource "aws_lambda_function" "metadata" {
  provider = aws.us_east_1

  function_name = local.lambda_metadata_name
  description   = "Lambda@Edge - Return SAML Service Provider metadata"
  role          = aws_iam_role.lambda_edge.arn
  handler       = "handlers/metadata.handler"
  runtime       = "nodejs22.x"
  timeout       = 5
  memory_size   = var.lambda_memory_size.metadata

  filename         = local.lambda_package
  source_code_hash = local.lambda_code_hash

  publish = true

  tags = var.tags

  depends_on = [null_resource.build_lambda]
}

# Login Lambda - starts the SAML flow for the sso-check CloudFront Function
resource "aws_lambda_function" "login" {
  provider = aws.us_east_1

  function_name = local.lambda_login_name
  description   = "Lambda@Edge - Start the SAML login flow"
  role          = aws_iam_role.lambda_edge.arn
  handler       = "handlers/login.handler"
  runtime       = "nodejs22.x"
  timeout       = 5
  memory_size   = var.lambda_memory_size.login

  filename         = local.lambda_package
  source_code_hash = local.lambda_code_hash

  publish = true

  tags = var.tags

  depends_on = [null_resource.build_lambda]
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
