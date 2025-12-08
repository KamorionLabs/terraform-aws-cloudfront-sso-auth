# -----------------------------------------------------------------------------
# Simple Example - CloudFront SSO Authentication
# -----------------------------------------------------------------------------

provider "aws" {
  region = "eu-west-3"
}

provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}

# -----------------------------------------------------------------------------
# SSO Authentication Module
# -----------------------------------------------------------------------------
module "cloudfront_sso_auth" {
  source = "../../"

  name          = "myapp-staging"
  saml_audience = "myapp-staging-cloudfront"

  # Download this from Identity Center after creating the SAML application
  idp_metadata = file("${path.module}/idp-metadata.xml")

  cloudfront_domains = [
    "app.staging.example.com",
  ]

  tags = {
    Environment = "staging"
    Project     = "myapp"
  }

  providers = {
    aws           = aws
    aws.us_east_1 = aws.us_east_1
  }
}

# -----------------------------------------------------------------------------
# Example CloudFront Distribution with SSO
# -----------------------------------------------------------------------------
resource "aws_cloudfront_distribution" "example" {
  enabled         = true
  is_ipv6_enabled = true
  comment         = "Example distribution with SSO"
  aliases         = ["app.staging.example.com"]

  origin {
    domain_name = "example-bucket.s3.eu-west-3.amazonaws.com"
    origin_id   = "S3-example"
  }

  # Default behavior with SSO protection
  default_cache_behavior {
    target_origin_id       = "S3-example"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    # SSO authentication Lambda
    lambda_function_association {
      event_type   = "viewer-request"
      lambda_arn   = module.cloudfront_sso_auth.lambda_protect_arn
      include_body = false
    }
  }

  # SAML ACS endpoint
  ordered_cache_behavior {
    path_pattern           = "/saml/acs"
    target_origin_id       = "S3-example"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods         = ["GET", "HEAD"]

    forwarded_values {
      query_string = true
      cookies {
        forward = "all"
      }
    }

    lambda_function_association {
      event_type   = "viewer-request"
      lambda_arn   = module.cloudfront_sso_auth.lambda_acs_arn
      include_body = true # Required for SAML POST
    }
  }

  # SAML metadata endpoint
  ordered_cache_behavior {
    path_pattern           = "/saml/metadata.xml"
    target_origin_id       = "S3-example"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

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
  }
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------
output "saml_metadata_url" {
  value = module.cloudfront_sso_auth.saml_metadata_urls
}

output "saml_acs_url" {
  value = module.cloudfront_sso_auth.saml_acs_urls
}
