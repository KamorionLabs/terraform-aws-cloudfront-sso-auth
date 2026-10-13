# terraform-aws-cloudfront-sso-auth

Protect CloudFront distributions with AWS IAM Identity Center (SSO) over SAML, without Cognito. The session check runs in a **CloudFront Function** or a **Lambda@Edge**, the SAML flow (`/saml/login`, `/saml/acs`, `/saml/metadata.xml`) in Lambda@Edge.

## How it works

1. A request reaches a protected behavior. The session check verifies the signed session cookie (HMAC-SHA256).
2. Without a valid session, the user is sent to Identity Center: through `/saml/login` (CloudFront Function) or directly (Lambda@Edge `protect`).
3. Identity Center POSTs the SAML assertion to `/saml/acs`, which validates it, sets the session cookie and sends the user back to the original URL.

Passive static assets (`GET`/`HEAD` on an image, font, stylesheet or media extension) are served without a session, so an expired cookie never breaks a page with a redirect to the login portal. Scripts, data and markup always stay gated.

## Choosing the session check

| | CloudFront Function `sso-check` | Lambda@Edge `protect` |
|---|---|---|
| Attach with | `function_association` (viewer-request) | `lambda_function_association` (viewer-request) |
| Behavior already has CloudFront Functions | yes (beside them, or composed into one) | **no**: AWS forbids mixing both kinds in viewer events |
| Behavior already has a viewer-request Lambda@Edge | no | no: check the session in that Lambda instead (see below) |
| Login redirect | `/saml/login` on the same host (login Lambda) | straight to Identity Center |
| `bypass_headers` (WAF-trusted requests) | no | yes |
| Cost and latency | sub-millisecond, cheapest | a Lambda@Edge invocation per request |

Default to the CloudFront Function; use `protect` when you need `bypass_headers`.

## Usage

### 1. Identity Center application (management account)

```hcl
module "identity_center_app" {
  source  = "KamorionLabs/cloudfront-sso-auth/aws//modules/identity-center-app"
  version = "~> 1.3"

  providers = { aws = aws.management }

  application_name      = "myapp-staging"
  application_start_url = "https://app.staging.example.com"
  assigned_group_names  = ["Developers", "QA"] # or assigned_groups / assigned_users (IDs), assigned_user_names
}
```

Then, in the Identity Center console, download the application's **IAM Identity Center SAML metadata file** (Actions → Edit configuration) as `idp-metadata.xml`.

### 2. SSO module (workload account)

```hcl
module "sso" {
  source  = "KamorionLabs/cloudfront-sso-auth/aws"
  version = "~> 1.3"

  providers = {
    aws           = aws
    aws.us_east_1 = aws.us_east_1 # Lambda@Edge lives in us-east-1
  }

  name               = "myapp-staging"
  saml_audience      = "myapp-staging-cloudfront"
  idp_metadata       = file("${path.module}/idp-metadata.xml")
  cloudfront_domains = ["app.staging.example.com"]
}
```

OpenTofu does not query the Terraform registry: use `source = "git::https://github.com/KamorionLabs/terraform-aws-cloudfront-sso-auth.git?ref=v1.3.1"` instead. The Lambda package is built during the apply: Node.js and npm must be available there.

### 3. Distribution

The SAML endpoints, each on its own behavior (caching disabled, query string forwarded):

```hcl
ordered_cache_behavior {
  path_pattern    = "/saml/acs"
  allowed_methods = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
  # ...
  lambda_function_association {
    event_type   = "viewer-request"
    lambda_arn   = module.sso.lambda_acs_arn
    include_body = true # the SAML assertion is POSTed
  }
}

# Same pattern, GET/HEAD, include_body = false:
#   /saml/login        -> module.sso.lambda_login_arn    (needed with the CloudFront Function)
#   /saml/metadata.xml -> module.sso.lambda_metadata_arn
```

Then the session check on `default_cache_behavior` and **every** protected `ordered_cache_behavior`, either:

**A. CloudFront Function**

```hcl
function_association {
  event_type   = "viewer-request"
  function_arn = module.sso.sso_check_function_arn
}
```

**B. Lambda@Edge**

```hcl
lambda_function_association {
  event_type   = "viewer-request"
  lambda_arn   = module.sso.lambda_protect_arn
  include_body = false
}
```

`module.sso.cloudfront_behaviors` returns the CloudFront Function association and the three SAML behaviors as a map, ready to merge into your own.

### 4. Finish the Identity Center application

- **ACS URL**: `https://<host>/saml/acs` (one per protected host, or the single `auth_host`, see below); **SAML audience**: `saml_audience`. `sp_metadata_xml` is the ready-to-upload SP metadata.
- **Attribute mappings**: Subject = `${user:email}`, in the format of `name_id_format` (`transient` by default, or set `name_id_format = "emailAddress"`). A mismatch makes Identity Center answer "No access".

## Options

### One login for many hosts (`cookie_domain`, `auth_host`)

By default the cookie is host-only and every host is its own ACS URL. With a common parent domain, one login and one ACS URL cover them all:

```hcl
cookie_domain = ".preprod.example.com"    # cookie sent to every host under it
auth_host     = "sso.preprod.example.com" # the only ACS URL
```

`auth_host` must serve the `/saml/*` behaviors. The cookie reaches every host under the domain, protected or not: pick the narrowest common parent.

Two instances whose cookies can reach the same host (for example a host-only instance on `tools.example.com` next to one with `cookie_domain = ".example.com"`) must set different `cookie_name` values, or each rejects and overwrites the other's session.

### WAF-trusted requests (`bypass_headers`, Lambda@Edge only)

When a WAF already decides who is trusted (an IP allowlist), it can insert a header that lets the request through `protect` without a session:

```hcl
bypass_headers = { "x-amzn-waf-trusted" = "bypass" } # WAF insert_header "trusted"
```

AWS WAF prefixes inserted headers with `x-amzn-waf-` but does not strip one sent by the client: **the same ACL must block requests already carrying an `x-amzn-waf-*` header**, otherwise anyone can skip the SSO.

### Composing with an existing CloudFront Function

A behavior takes one function per event. Compose the check into the existing one (about 2 KB of the 10 KB limit):

```hcl
code = join("\n", [
  module.sso.sso_check_import_js, # imports first
  replace(file("my-function.js"), "async function handler(event) {", "async function myHandler(event) {"),
  module.sso.sso_check_library_js, # defines ssoCheck(event)
  "async function handler(event) {",
  "    return ssoCheck(event) || myHandler(event);",
  "}",
])
```

### Checking the session in your own Lambda@Edge

When a behavior already has a viewer-request Lambda@Edge (bot protection, say), verify the session inside it with `session_hmac_key` (sensitive), `saml_audience` and `session_cookie_name`, and redirect requests without a valid session to `saml_login_path?relay=<path and query>`. Token: `v1.<expiry epoch seconds>.<hex utf-8 email>.<hex HMAC-SHA256>`, the MAC covering `<audience>|v1.<expiry>.<email hex>` (`lambda/src/shared/utils/token.ts`). Let static assets through on the request line only (method, extension), never on a request header.

### Faster logins (`lambda_memory_size`)

At 128 MB, validating the signed assertion in `acs` takes about 2 s. `login`, `acs` and `metadata` can run on **origin-request** (their behaviors are not cached), where up to 10 240 MB is allowed:

```hcl
lambda_memory_size = { login = 1024, acs = 1024 }
```

Associate them with `event_type = "origin-request"` and an origin request policy forwarding `Host` and the query string (e.g. `Managed-AllViewer`). CloudFront rejects origin-request Lambda@Edge on VPC origins. `protect` stays on viewer-request at 128 MB.

## Inputs

| Name | Description | Default |
|------|-------------|---------|
| `name` | Name of the resources | required |
| `saml_audience` | SAML audience (SP entity ID) | required |
| `idp_metadata` | Identity Center SAML metadata XML | required |
| `cloudfront_domains` | Protected hosts (ACS URLs in per-host mode) | `[]` |
| `session_duration_hours` | Session lifetime, 1 to 24 | `8` |
| `cookie_domain` | Parent domain of the session cookie (leading dot); empty: host-only | `""` |
| `auth_host` | Single host receiving every assertion; requires `cookie_domain` | `""` |
| `cookie_name` | Session cookie name; must differ between instances whose cookies can reach the same host | `"sso_auth"` |
| `name_id_format` | NameID format requested: `transient`, `persistent`, `emailAddress`, `unspecified` | `"transient"` |
| `bypass_headers` | `{ name = value }` (lowercase) letting a request through `protect` without a session | `{}` |
| `lambda_memory_size` | Memory per function (`login`, `acs`, `metadata`, `protect`); above 128 MB needs origin-request | `{}` (128 MB) |
| `sign_authn_requests` | Sign the SAML AuthnRequests | `false` |
| `name_prefix` | Prefix of the resource names | `""` (`name`) |
| `log_retention_days` | CloudWatch log retention | `7` |
| `tags` | Tags | `{}` |

## Outputs

| Name | Description |
|------|-------------|
| `sso_check_function_arn` | CloudFront Function, viewer-request on protected behaviors |
| `sso_check_import_js`, `sso_check_library_js` | Pieces to compose the check into another function (library sensitive) |
| `lambda_protect_arn`, `lambda_login_arn`, `lambda_acs_arn`, `lambda_metadata_arn` | Lambda@Edge qualified ARNs |
| `cloudfront_behaviors` | Ready-made association and SAML behaviors |
| `saml_login_path`, `saml_acs_path`, `saml_metadata_path`, `saml_logout_path` | SAML paths |
| `saml_acs_urls`, `saml_metadata_urls`, `sp_metadata_xml` | Identity Center configuration |
| `saml_audience`, `saml_signing_certificate` (sensitive) | SP identity |
| `session_hmac_key` (sensitive), `session_cookie_name`, `session_cookie_domain` | Session check in your own code |
| `secrets_manager_arn` | Secret holding the SAML configuration |

Requirements: Terraform or OpenTofu >= 1.5; providers `aws` >= 5.0 (with an `aws.us_east_1` alias), `random`, `archive`, `null`, `tls`, `local`.

## Security

- Session cookies are signed with HMAC-SHA256, the MAC covering the SAML audience; `HttpOnly`, `Secure`, `SameSite=Lax`.
- The HMAC key is baked into the Lambda@Edge package and the CloudFront Function code (neither can read Secrets Manager at runtime): anyone allowed to read those functions can read it. Rotate it with `apply -replace=module.<name>.random_password.hmac_key` (everyone signs in again).
- `x-sso-user-email`, forwarded to the origin for authenticated requests, is always removed from the viewer request first.
- The static asset passthrough depends on the request line only (`GET`/`HEAD`, asset extension, no `;` path parameter), never on `Sec-Fetch-Dest` or any other client header.
- `/saml/login` and the ACS only follow same-site relay targets (no open redirect).

## Upgrading

- **To 1.3.1**: security fix, nothing to change. Earlier 1.x versions let any request carrying `Sec-Fetch-Dest: image` through without a session: upgrade.
- **0.x to 1.0**: the cookie is signed instead of encrypted (everyone signs in again once); replace the `protect` association with `sso_check_function_arn` (or keep `protect`, which verifies the new cookie) and add the `/saml/login` behavior.

## Credits

Based on [Use IAM Identity Center (AWS SSO) to Protect your CloudFront](https://www.sls.guru/blog/use-iam-identity-center-aws-sso-to-protect-your-cloudfront-served-application) by Serverless Guru and [Cloudfront-Auth-IAM-Identity-Center](https://github.com/DanielMuller/Cloudfront-Auth-IAM-Identity-Center) by Daniel Muller.

## License

MIT. Maintained by [Kamorion](https://kamorion.com).
