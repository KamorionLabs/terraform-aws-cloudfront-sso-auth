# -----------------------------------------------------------------------------
# Complete Example - CloudFront SSO with Identity Center Application
#
# This example shows the full setup including:
# - Identity Center SAML application (in management account)
# - Lambda@Edge authentication (in workload account)
# - CloudFront distribution integration
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Provider Configuration
# -----------------------------------------------------------------------------
provider "aws" {
  region  = "eu-west-3"
  profile = "workload-account"
}

provider "aws" {
  alias   = "us_east_1"
  region  = "us-east-1"
  profile = "workload-account"
}

provider "aws" {
  alias   = "management"
  region  = "eu-west-1" # Or your Identity Center region
  profile = "management-account"
}

# -----------------------------------------------------------------------------
# Variables
# -----------------------------------------------------------------------------
variable "environment" {
  default = "staging"
}

variable "project" {
  default = "myapp"
}

variable "domains" {
  default = [
    "fr.staging.myapp.example.com",
    "de.staging.myapp.example.com",
    "es.staging.myapp.example.com",
  ]
}

locals {
  name          = "${var.project}-${var.environment}"
  saml_audience = "${local.name}-cloudfront-sso"
}

# -----------------------------------------------------------------------------
# Step 1: Create Identity Center Application (Management Account)
# -----------------------------------------------------------------------------
module "identity_center_app" {
  source = "../../modules/identity-center-app"

  providers = {
    aws = aws.management
  }

  application_name        = local.name
  application_description = "SSO access to ${var.project} ${var.environment} environment"
  application_start_url   = "https://${var.domains[0]}"

  # Assign access by group name
  assigned_group_names = [
    "Developers",
    "QA-Team",
  ]

  # Or by specific user names
  assigned_user_names = [
    "admin@example.com",
  ]

  tags = {
    Environment = var.environment
    Project     = var.project
  }
}

# -----------------------------------------------------------------------------
# Step 2: Create Lambda@Edge Functions (Workload Account)
# Note: You need to download the IdP metadata from Identity Center
#       after Step 1 and save it to idp-metadata.xml
# -----------------------------------------------------------------------------
module "cloudfront_sso_auth" {
  source = "../../"

  providers = {
    aws           = aws
    aws.us_east_1 = aws.us_east_1
  }

  name          = local.name
  saml_audience = local.saml_audience

  # Download this from Identity Center console after creating the application:
  # Applications > [your app] > Actions > Edit configuration > Download metadata
  idp_metadata = file("${path.module}/idp-metadata.xml")

  cloudfront_domains = var.domains

  log_retention_days = 7

  tags = {
    Environment = var.environment
    Project     = var.project
  }
}

# -----------------------------------------------------------------------------
# Step 3: Configure CloudFront Distribution
# -----------------------------------------------------------------------------
resource "aws_cloudfront_distribution" "main" {
  enabled         = true
  is_ipv6_enabled = true
  comment         = "${local.name} CloudFront Distribution"
  aliases         = var.domains

  # Your existing origins here...
  origin {
    domain_name = "my-bucket.s3.eu-west-3.amazonaws.com"
    origin_id   = "S3-main"
  }

  # Default behavior - SSO protected
  default_cache_behavior {
    target_origin_id       = "S3-main"
    viewer_protocol_policy = "redirect-to-https"
    compress               = true

    allowed_methods = ["GET", "HEAD", "OPTIONS"]
    cached_methods  = ["GET", "HEAD"]

    forwarded_values {
      query_string = true
      headers      = ["Host"]
      cookies {
        forward = "all"
      }
    }

    min_ttl     = 0
    default_ttl = 0
    max_ttl     = 0

    # SSO Protection Lambda
    lambda_function_association {
      event_type   = "viewer-request"
      lambda_arn   = module.cloudfront_sso_auth.lambda_protect_arn
      include_body = false
    }
  }

  # SAML ACS endpoint - handles login callback
  ordered_cache_behavior {
    path_pattern           = "/saml/acs"
    target_origin_id       = "S3-main"
    viewer_protocol_policy = "redirect-to-https"

    allowed_methods = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods  = ["GET", "HEAD"]

    forwarded_values {
      query_string = true
      cookies {
        forward = "all"
      }
    }

    min_ttl     = 0
    default_ttl = 0
    max_ttl     = 0

    lambda_function_association {
      event_type   = "viewer-request"
      lambda_arn   = module.cloudfront_sso_auth.lambda_acs_arn
      include_body = true # IMPORTANT: Required for SAML POST body
    }
  }

  # SAML Metadata endpoint - for Identity Center configuration
  ordered_cache_behavior {
    path_pattern           = "/saml/metadata.xml"
    target_origin_id       = "S3-main"
    viewer_protocol_policy = "redirect-to-https"

    allowed_methods = ["GET", "HEAD", "OPTIONS"]
    cached_methods  = ["GET", "HEAD"]

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    min_ttl     = 0
    default_ttl = 86400
    max_ttl     = 86400

    lambda_function_association {
      event_type   = "viewer-request"
      lambda_arn   = module.cloudfront_sso_auth.lambda_metadata_arn
      include_body = false
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
    # Or use your ACM certificate:
    # acm_certificate_arn      = aws_acm_certificate.main.arn
    # ssl_support_method       = "sni-only"
    # minimum_protocol_version = "TLSv1.2_2021"
  }
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------
output "identity_center_instructions" {
  value = module.identity_center_app.saml_configuration_instructions
}

output "saml_metadata_urls" {
  description = "Visit these URLs to get SP metadata for Identity Center"
  value       = module.cloudfront_sso_auth.saml_metadata_urls
}

output "saml_acs_urls" {
  description = "Configure these as ACS URLs in Identity Center"
  value       = module.cloudfront_sso_auth.saml_acs_urls
}

output "saml_audience" {
  description = "Configure this as SAML audience in Identity Center"
  value       = module.cloudfront_sso_auth.saml_audience
}
