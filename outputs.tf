# -----------------------------------------------------------------------------
# Lambda ARNs for CloudFront association
# -----------------------------------------------------------------------------

output "lambda_protect_arn" {
  description = "Qualified ARN of the protect Lambda@Edge function. Alternative to sso_check_function_arn for behaviors that carry no CloudFront Function (viewer-request)."
  value       = aws_lambda_function.protect.qualified_arn
}

output "lambda_login_arn" {
  description = "Qualified ARN of the login Lambda@Edge function (for viewer-request on /saml/login, required with the sso-check CloudFront Function)"
  value       = aws_lambda_function.login.qualified_arn
}

output "lambda_acs_arn" {
  description = "Qualified ARN of the ACS Lambda@Edge function (for viewer-request on /saml/acs)"
  value       = aws_lambda_function.acs.qualified_arn
}

output "lambda_metadata_arn" {
  description = "Qualified ARN of the metadata Lambda@Edge function (for viewer-request on /saml/metadata.xml)"
  value       = aws_lambda_function.metadata.qualified_arn
}

# -----------------------------------------------------------------------------
# sso-check CloudFront Function
# -----------------------------------------------------------------------------

output "sso_check_function_arn" {
  description = "ARN of the sso-check CloudFront Function (for viewer-request on every protected behavior)"
  value       = aws_cloudfront_function.sso_check.arn
}

output "sso_check_import_js" {
  description = "Import line the sso-check library needs. Must sit at the top of a composed function, next to its other imports."
  value       = local.sso_check_import_js
}

output "sso_check_library_js" {
  description = "sso-check library (defines ssoCheck(event)), to compose with another viewer-request CloudFront Function on the same behavior. Contains the HMAC key."
  value       = local.sso_check_library_js
  sensitive   = true
}

# -----------------------------------------------------------------------------
# SAML Configuration
# -----------------------------------------------------------------------------

output "saml_acs_path" {
  description = "SAML Assertion Consumer Service path to configure in CloudFront"
  value       = local.saml_acs_path
}

output "saml_metadata_path" {
  description = "SAML metadata.xml path to configure in CloudFront"
  value       = local.saml_metadata_path
}

output "saml_login_path" {
  description = "SAML login path to configure in CloudFront (login Lambda)"
  value       = local.saml_login_path
}

output "saml_audience" {
  description = "SAML audience (EntityID) configured for this module"
  value       = var.saml_audience
}

# -----------------------------------------------------------------------------
# For Identity Center Configuration
# -----------------------------------------------------------------------------

output "saml_acs_urls" {
  description = "SAML ACS URLs to configure in Identity Center (one per domain)"
  value       = [for domain in local.acs_domains : "https://${domain}${local.saml_acs_path}"]
}

output "saml_metadata_urls" {
  description = "URLs to download SP metadata after deployment (one per domain)"
  value       = [for domain in local.acs_domains : "https://${domain}${local.saml_metadata_path}"]
}

# -----------------------------------------------------------------------------
# SP Metadata XML (for Identity Center upload)
# -----------------------------------------------------------------------------

output "sp_metadata_xml" {
  description = "Complete SP metadata XML with all ACS URLs, ready to upload to Identity Center SAML application configuration"
  value       = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor
  xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
  entityID="${var.saml_audience}">
    <md:SPSSODescriptor AuthnRequestsSigned="${var.sign_authn_requests}" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:KeyDescriptor use="signing">
            <ds:KeyInfo>
                <ds:X509Data>
                    <ds:X509Certificate>${replace(replace(replace(tls_self_signed_cert.saml_signing.cert_pem, "-----BEGIN CERTIFICATE-----", ""), "-----END CERTIFICATE-----", ""), "\n", "")}</ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </md:KeyDescriptor>
        <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
${join("\n", [for i, domain in local.acs_domains : "        <md:AssertionConsumerService${i == 0 ? " isDefault=\"true\"" : ""} index=\"${i}\" Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://${domain}${local.saml_acs_path}\"/>"])}
    </md:SPSSODescriptor>
</md:EntityDescriptor>
XML
}

# -----------------------------------------------------------------------------
# Secrets
# -----------------------------------------------------------------------------

output "secrets_manager_arn" {
  description = "ARN of the Secrets Manager secret containing SAML configuration"
  value       = aws_secretsmanager_secret.saml_config.arn
}

# -----------------------------------------------------------------------------
# SAML Signing Certificate
# -----------------------------------------------------------------------------

output "saml_signing_certificate" {
  description = "SAML signing certificate in PEM format (for Identity Center configuration if needed)"
  value       = tls_self_signed_cert.saml_signing.cert_pem
  sensitive   = true
}

# -----------------------------------------------------------------------------
# CloudFront Cache Behaviors Configuration (for reference)
# -----------------------------------------------------------------------------

output "cloudfront_behaviors" {
  description = "CloudFront cache behaviors configuration to add for SSO authentication"
  value = {
    # Add this to the default_cache_behavior and every protected ordered_cache_behavior
    protected = {
      function_association = {
        event_type   = "viewer-request"
        function_arn = aws_cloudfront_function.sso_check.arn
      }
    }
    # Add these as ordered_cache_behavior
    saml_login = {
      path_pattern = local.saml_login_path
      lambda_function_association = {
        event_type   = "viewer-request"
        lambda_arn   = aws_lambda_function.login.qualified_arn
        include_body = false
      }
      allowed_methods = ["GET", "HEAD"]
    }
    saml_acs = {
      path_pattern = local.saml_acs_path
      lambda_function_association = {
        event_type   = "viewer-request"
        lambda_arn   = aws_lambda_function.acs.qualified_arn
        include_body = true # Required for SAML POST
      }
      allowed_methods = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    }
    saml_metadata = {
      path_pattern = local.saml_metadata_path
      lambda_function_association = {
        event_type   = "viewer-request"
        lambda_arn   = aws_lambda_function.metadata.qualified_arn
        include_body = false
      }
      allowed_methods = ["GET", "HEAD", "OPTIONS"]
    }
  }
}

# -----------------------------------------------------------------------------
# Session token, for a session check running outside this module (e.g. inside
# an existing viewer-request Lambda@Edge that cannot share its behavior with
# the protect Lambda or the sso-check CloudFront Function)
# -----------------------------------------------------------------------------

output "session_hmac_key" {
  description = "HMAC-SHA256 key signing the session cookie. Token: v1.<expiry epoch seconds>.<hex utf-8 email>.<hex HMAC>, the MAC covering \"<saml_audience>|v1.<expiry>.<email hex>\"."
  value       = random_password.hmac_key.result
  sensitive   = true
}

output "session_cookie_name" {
  description = "Name of the session cookie set by the ACS Lambda"
  value       = local.cookie_name
}

output "saml_logout_path" {
  description = "Path clearing the session cookie"
  value       = local.saml_logout_path
}

output "session_cookie_domain" {
  description = "Domain of the session cookie (empty: host-only)"
  value       = var.cookie_domain
}
