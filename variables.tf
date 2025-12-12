# -----------------------------------------------------------------------------
# Required Variables
# -----------------------------------------------------------------------------

variable "name" {
  description = "Name used for resources (e.g., 'myapp-staging')"
  type        = string
}

variable "saml_audience" {
  description = "SAML audience identifier (EntityID). Must match the Identity Center application configuration."
  type        = string
}

variable "idp_metadata" {
  description = "Identity Provider SAML metadata XML content. Download from Identity Center application settings."
  type        = string
  sensitive   = true
}

# -----------------------------------------------------------------------------
# Optional Variables
# -----------------------------------------------------------------------------

variable "name_prefix" {
  description = "Prefix for resource names. Defaults to var.name if not specified."
  type        = string
  default     = ""
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days for Lambda@Edge functions"
  type        = number
  default     = 7
}

variable "cloudfront_domains" {
  description = "List of CloudFront domain names (aliases) that will use SSO authentication. Used to generate ACS URLs for Identity Center."
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}

variable "sign_authn_requests" {
  description = "Whether to sign SAML AuthnRequests. Set to false if the IDP metadata has WantAuthnRequestsSigned=false (default for AWS Identity Center)."
  type        = bool
  default     = false
}
