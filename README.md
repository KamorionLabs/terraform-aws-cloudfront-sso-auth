# terraform-aws-cloudfront-sso-auth

Terraform module to protect CloudFront distributions with AWS Identity Center (SSO) authentication using SAML and Lambda@Edge.

## Credits

This module is based on the excellent work by:
- **Blog post**: [Use IAM Identity Center (AWS SSO) to Protect your CloudFront](https://www.sls.guru/blog/use-iam-identity-center-aws-sso-to-protect-your-cloudfront-served-application) by Serverless Guru
- **Original implementation**: [Cloudfront-Auth-IAM-Identity-Center](https://github.com/DanielMuller/Cloudfront-Auth-IAM-Identity-Center) by Daniel Muller

## Features

- SAML-based authentication with AWS Identity Center
- No Cognito dependency - direct integration with Identity Center
- Three Lambda@Edge functions for complete SAML flow
- Support for multiple CloudFront domains/aliases
- Encrypted session cookies (AES-256)
- Sub-module for Identity Center SAML application setup

## Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Browser   │────▶│   CloudFront     │────▶│  Origin (S3/ALB)│
└─────────────┘     └──────────────────┘     └─────────────────┘
       │                    │
       │              ┌─────┴─────┐
       │              │Lambda@Edge│
       │              │ (protect) │
       │              └─────┬─────┘
       │                    │
       │    No valid cookie │
       │◀───────────────────┘
       │    Redirect to IdP
       │
       ▼
┌─────────────────────┐
│  Identity Center    │
│   (SAML Login)      │
└─────────────────────┘
       │
       │ SAML Assertion POST
       ▼
┌──────────────────┐
│   CloudFront     │
│   /saml/acs      │
└──────────────────┘
       │
       │ Lambda@Edge (acs)
       │ Validate & Set Cookie
       ▼
┌─────────────┐
│  Redirect   │
│  to App     │
└─────────────┘
```

## Usage

### Step 1: Create Identity Center Application (Management Account)

```hcl
module "identity_center_app" {
  source = "github.com/kamorion/terraform-aws-cloudfront-sso-auth//modules/identity-center-app"

  providers = {
    aws = aws.management
  }

  application_name      = "myapp-staging"
  application_start_url = "https://app.staging.example.com"

  assigned_group_names = ["Developers", "QA"]
}
```

### Step 2: Download IdP Metadata

After applying Step 1, go to Identity Center console:
1. Applications → [your app] → Actions → Edit configuration
2. Download "IAM Identity Center SAML metadata file"
3. Save as `idp-metadata.xml`

### Step 3: Deploy Lambda@Edge Functions (Workload Account)

```hcl
module "cloudfront_sso_auth" {
  source = "github.com/kamorion/terraform-aws-cloudfront-sso-auth"

  providers = {
    aws           = aws
    aws.us_east_1 = aws.us_east_1
  }

  name          = "myapp-staging"
  saml_audience = "myapp-staging-cloudfront"
  idp_metadata  = file("${path.module}/idp-metadata.xml")

  cloudfront_domains = ["app.staging.example.com"]
}
```

### Step 4: Configure CloudFront Distribution

```hcl
resource "aws_cloudfront_distribution" "main" {
  # ... your existing config ...

  # Default behavior with SSO protection
  default_cache_behavior {
    # ... your config ...

    lambda_function_association {
      event_type   = "viewer-request"
      lambda_arn   = module.cloudfront_sso_auth.lambda_protect_arn
      include_body = false
    }
  }

  # SAML ACS endpoint
  ordered_cache_behavior {
    path_pattern    = "/saml/acs"
    allowed_methods = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    # ... your config ...

    lambda_function_association {
      event_type   = "viewer-request"
      lambda_arn   = module.cloudfront_sso_auth.lambda_acs_arn
      include_body = true  # IMPORTANT: Required for SAML POST
    }
  }

  # SAML metadata endpoint
  ordered_cache_behavior {
    path_pattern = "/saml/metadata.xml"
    # ... your config ...

    lambda_function_association {
      event_type   = "viewer-request"
      lambda_arn   = module.cloudfront_sso_auth.lambda_metadata_arn
      include_body = false
    }
  }
}
```

### Step 5: Complete Identity Center Configuration

1. Deploy your CloudFront distribution
2. Visit `https://your-domain/saml/metadata.xml` to get SP metadata
3. Go back to Identity Center → Applications → [your app]
4. Upload the SP metadata or configure manually:
   - ACS URL: `https://your-domain/saml/acs`
   - SAML Audience: Your `saml_audience` value

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.5 |
| aws | >= 5.0 |
| random | >= 3.5 |
| archive | >= 2.4 |
| null | >= 3.2 |

## Providers

| Name | Purpose |
|------|---------|
| aws | Default provider for regional resources |
| aws.us_east_1 | Required for Lambda@Edge (must be us-east-1) |

## Inputs

| Name | Description | Type | Required |
|------|-------------|------|----------|
| name | Name used for resources | string | yes |
| saml_audience | SAML audience identifier (EntityID) | string | yes |
| idp_metadata | Identity Provider SAML metadata XML | string | yes |
| cloudfront_domains | List of CloudFront domain names | list(string) | no |
| name_prefix | Prefix for resource names | string | no |
| log_retention_days | CloudWatch log retention | number | no |
| tags | Tags to apply | map(string) | no |

## Outputs

| Name | Description |
|------|-------------|
| lambda_protect_arn | ARN of protect Lambda (for default behavior) |
| lambda_acs_arn | ARN of ACS Lambda (for /saml/acs) |
| lambda_metadata_arn | ARN of metadata Lambda (for /saml/metadata.xml) |
| saml_acs_urls | ACS URLs for Identity Center configuration |
| saml_metadata_urls | URLs to download SP metadata |
| secrets_manager_arn | ARN of Secrets Manager secret |

## Sub-modules

### identity-center-app

Creates the SAML application in Identity Center. Deploy this in your management/identity account.

```hcl
module "identity_center_app" {
  source = "github.com/kamorion/terraform-aws-cloudfront-sso-auth//modules/identity-center-app"

  application_name      = "myapp-staging"
  application_start_url = "https://app.example.com"

  # Assign by group/user names
  assigned_group_names = ["Developers"]
  assigned_user_names  = ["admin@example.com"]

  # Or by IDs
  assigned_groups = ["group-id-1"]
  assigned_users  = ["user-id-1"]
}
```

## Manual Steps Required

Due to AWS API limitations, some configuration must be done manually:

1. **Download IdP Metadata**: After creating the Identity Center application, download the SAML metadata file from the console
2. **Upload SP Metadata**: After deploying CloudFront, upload the SP metadata.xml to Identity Center

## Security Considerations

- Session cookies are encrypted with AES-256-CBC
- Encryption keys are stored in Secrets Manager
- Lambda@Edge cannot access Secrets Manager at runtime, so keys are baked into the code at build time
- Consider rotating the encryption keys periodically by updating the Secrets Manager secret and redeploying

## License

MIT

## Authors

Kamorion - [https://kamorion.com](https://kamorion.com)
