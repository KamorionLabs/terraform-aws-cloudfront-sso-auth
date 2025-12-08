# -----------------------------------------------------------------------------
# Application Outputs
# -----------------------------------------------------------------------------

output "application_arn" {
  description = "ARN of the Identity Center application"
  value       = aws_ssoadmin_application.this.arn
}

output "application_id" {
  description = "ID of the Identity Center application"
  value       = aws_ssoadmin_application.this.id
}

# -----------------------------------------------------------------------------
# SAML Configuration - IMPORTANT
# These values must be configured manually in Identity Center console
# -----------------------------------------------------------------------------

output "saml_configuration_instructions" {
  description = "Instructions for completing SAML configuration in Identity Center"
  value       = <<-EOT

    ============================================================
    MANUAL CONFIGURATION REQUIRED IN IDENTITY CENTER CONSOLE
    ============================================================

    The Terraform AWS provider does not yet support configuring
    SAML metadata for custom applications. You must complete the
    following steps manually:

    1. Go to AWS Identity Center Console
    2. Navigate to: Applications > ${var.application_name}
    3. Click "Actions" > "Edit configuration"
    4. In the "Application metadata" section:
       - Upload the SP metadata.xml file from your CloudFront domain:
         https://<your-domain>/saml/metadata.xml

       OR manually configure:
       - Application ACS URL: https://<your-domain>/saml/acs
       - Application SAML audience: <your-saml-audience>

    5. Download the "IAM Identity Center SAML metadata file"
       - This XML file is needed for the Lambda@Edge module
       - Pass it as the 'idp_metadata' variable

    6. Configure Attribute Mappings:
       - Subject: $${user:subject} (format: transient)

    ============================================================
  EOT
}

output "instance_arn" {
  description = "ARN of the Identity Center instance"
  value       = local.instance_arn
}

output "identity_store_id" {
  description = "ID of the Identity Store"
  value       = local.identity_store_id
}
