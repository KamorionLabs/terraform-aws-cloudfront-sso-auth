# terraform-aws-cloudfront-sso-auth

Terraform module to protect CloudFront distributions with AWS Identity Center (SSO) authentication using SAML, a CloudFront Function for the session check and Lambda@Edge for the SAML flow.

## Credits

This module is based on the excellent work by:
- **Blog post**: [Use IAM Identity Center (AWS SSO) to Protect your CloudFront](https://www.sls.guru/blog/use-iam-identity-center-aws-sso-to-protect-your-cloudfront-served-application) by Serverless Guru
- **Original implementation**: [Cloudfront-Auth-IAM-Identity-Center](https://github.com/DanielMuller/Cloudfront-Auth-IAM-Identity-Center) by Daniel Muller

## Features

- SAML-based authentication with AWS Identity Center
- No Cognito dependency - direct integration with Identity Center
- Session check in a CloudFront Function (`sso-check`), attachable to every cache behavior, even those already carrying other CloudFront Functions
- Lambda@Edge functions for the SAML flow (`login`, `acs`, `metadata`), plus a Lambda-only `protect` alternative
- Support for multiple CloudFront domains/aliases
- Signed session cookies (HMAC-SHA256), configurable lifetime
- Sub-module for Identity Center SAML application setup

### Why a CloudFront Function for the session check

AWS forbids combining CloudFront Functions and Lambda@Edge in the viewer events of one cache behavior (both events together, not only the same one). A Lambda@Edge gate can therefore only sit on behaviors without CloudFront Functions, which in practice leaves most of a site unprotected. The `sso-check` function verifies the cookie in under a millisecond at every edge location, and can be composed with another viewer-request function on the same behavior (`sso_check_import_js` + `sso_check_library_js`).

## Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Browser   │────▶│   CloudFront     │────▶│  Origin (S3/ALB)│
└─────────────┘     └──────────────────┘     └─────────────────┘
       │                    │
       │           ┌────────┴────────┐
       │           │CloudFront Func. │
       │           │   (sso-check)   │
       │           └────────┬────────┘
       │                    │
       │    No valid cookie │ 302 /saml/login?relay=...
       │◀───────────────────┘
       │
       ▼
┌──────────────────┐
│   /saml/login    │  Lambda@Edge (login): signed AuthnRequest
└──────────────────┘
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

  # Default behavior with SSO protection. Add the same association to EVERY
  # ordered_cache_behavior that must be protected.
  default_cache_behavior {
    # ... your config ...

    function_association {
      event_type   = "viewer-request"
      function_arn = module.cloudfront_sso_auth.sso_check_function_arn
    }
  }

  # SAML login endpoint (where sso-check redirects)
  ordered_cache_behavior {
    path_pattern    = "/saml/login"
    allowed_methods = ["GET", "HEAD"]
    # ... your config, query string forwarded ...

    lambda_function_association {
      event_type   = "viewer-request"
      lambda_arn   = module.cloudfront_sso_auth.lambda_login_arn
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

### Composing with an existing viewer-request function

A behavior takes one function per event. When a behavior already has a viewer-request CloudFront Function, compose the check into it instead of attaching `sso-check` beside it:

```hcl
code = join("\n", [
  module.cloudfront_sso_auth.sso_check_import_js, # imports first
  replace(file("my-function.js"), "async function handler(event) {", "async function myHandler(event) {"),
  module.cloudfront_sso_auth.sso_check_library_js, # defines ssoCheck(event)
  "async function handler(event) {",
  "    return ssoCheck(event) || myHandler(event);",
  "}",
])
```

The library is about 2 KB once deployed (the limit is 10 KB per function).

### Letting upstream-trusted requests through (bypass_headers)

When a WAF already decides which requests are trusted (an IP allowlist, for instance), it can mark them with an inserted header and the `protect` Lambda lets them through without an SSO session:

```hcl
bypass_headers = {
  "x-amzn-waf-trusted" = "bypass" # WAF custom_request_handling insert_header "trusted"
}
```

AWS WAF prefixes inserted headers with `x-amzn-waf-`, but it does not strip one sent by the client: the same ACL must block requests that already carry an `x-amzn-waf-*` header, otherwise anyone can skip the SSO by sending it. Only `protect` honours `bypass_headers`; `sso-check` does not.

### Checking the session in your own Lambda@Edge

A behavior takes one viewer-request Lambda@Edge. When it already has one (a bot-protection Lambda, say), verify the session inside it instead: `session_hmac_key` (sensitive), `saml_audience` and `session_cookie_name` are enough to check the token, and a request without a valid session is redirected to `saml_login_path?relay=<path and query>`. The token format is `v1.<expiry epoch seconds>.<hex utf-8 email>.<hex HMAC-SHA256>`, the MAC covering `<audience>|v1.<expiry>.<email hex>` (see `lambda/src/shared/utils/token.ts`). Route `/saml/login`, `/saml/acs` and `/saml/metadata.xml` to the module's Lambdas on their own behaviors, as in Step 4.

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
| session_duration_hours | Session cookie lifetime (1-24, default 8) | number | no |
| sign_authn_requests | Sign SAML AuthnRequests | bool | no |
| bypass_headers | Headers (`{ name = value }`, lowercase names) letting a request through `protect` without a session; unforgeable headers only | map(string) | no |
| name_prefix | Prefix for resource names | string | no |
| log_retention_days | CloudWatch log retention | number | no |
| tags | Tags to apply | map(string) | no |

## Outputs

| Name | Description |
|------|-------------|
| sso_check_function_arn | ARN of the sso-check CloudFront Function (viewer-request on protected behaviors) |
| sso_check_import_js / sso_check_library_js | Pieces to compose sso-check into another function (library is sensitive) |
| lambda_login_arn | ARN of login Lambda (for /saml/login) |
| lambda_protect_arn | ARN of protect Lambda (Lambda-only alternative to sso-check) |
| lambda_acs_arn | ARN of ACS Lambda (for /saml/acs) |
| lambda_metadata_arn | ARN of metadata Lambda (for /saml/metadata.xml) |
| saml_acs_urls | ACS URLs for Identity Center configuration |
| saml_metadata_urls | URLs to download SP metadata |
| secrets_manager_arn | ARN of Secrets Manager secret |
| session_hmac_key | Key signing the session cookie, for a session check in your own Lambda (sensitive) |
| session_cookie_name | Name of the session cookie |
| saml_logout_path | Path clearing the session cookie |

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

- Session cookies are signed with HMAC-SHA256 (`v1.<expiry>.<hex email>.<mac>`), the MAC also covering the SAML audience; they are HttpOnly, Secure, SameSite=Lax
- The HMAC key (`random_password.hmac_key`) is baked into the Lambda@Edge package and the CloudFront Function code at deploy time (neither can read Secrets Manager at runtime): anyone allowed to read those functions can read it
- Rotating the key (`terraform apply -replace=module.<name>.random_password.hmac_key`) signs everyone out once
- `x-sso-user-email`, forwarded to the origin for authenticated requests, is always removed from the viewer request first, so it cannot be spoofed
- `/saml/login` only accepts same-site, path-absolute relay targets (no open redirect)

## Upgrading from 0.x to 1.0

- The cookie format changes (signed instead of AES-encrypted): every user signs in again once after the apply.
- Replace the `protect` Lambda@Edge association with a `function_association` to `sso_check_function_arn` on the default behavior and every protected ordered behavior, and add the `/saml/login` behavior (login Lambda). `protect` still exists and verifies the new cookie, for setups that cannot use CloudFront Functions.
- `random_password.init_vector` and `random_password.private_key` are destroyed; `random_password.hmac_key` is created.

## License

MIT

## Authors

Kamorion - [https://kamorion.com](https://kamorion.com)
