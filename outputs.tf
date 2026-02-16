# -----------------------------------------------------------------------------
# Lambda ARNs for CloudFront association
# -----------------------------------------------------------------------------

output "lambda_protect_arn" {
  description = "Qualified ARN of the protect Lambda@Edge function (for viewer-request on default behavior)"
  value       = aws_lambda_function.protect.qualified_arn
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

output "saml_audience" {
  description = "SAML audience (EntityID) configured for this module"
  value       = var.saml_audience
}

# -----------------------------------------------------------------------------
# For Identity Center Configuration
# -----------------------------------------------------------------------------

output "saml_acs_urls" {
  description = "SAML ACS URLs to configure in Identity Center (one per domain)"
  value       = [for domain in var.cloudfront_domains : "https://${domain}${local.saml_acs_path}"]
}

output "saml_metadata_urls" {
  description = "URLs to download SP metadata after deployment (one per domain)"
  value       = [for domain in var.cloudfront_domains : "https://${domain}${local.saml_metadata_path}"]
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
${join("\n", [for i, domain in var.cloudfront_domains : "        <md:AssertionConsumerService${i == 0 ? " isDefault=\"true\"" : ""} index=\"${i}\" Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://${domain}${local.saml_acs_path}\"/>"])}
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
    # Add this to your default_cache_behavior
    default = {
      lambda_function_association = {
        event_type   = "viewer-request"
        lambda_arn   = aws_lambda_function.protect.qualified_arn
        include_body = false
      }
    }
    # Add these as ordered_cache_behavior
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
