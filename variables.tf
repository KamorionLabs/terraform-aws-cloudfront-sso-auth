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

variable "session_duration_hours" {
  description = "Lifetime of the SSO session cookie, in hours. Decoupled from the SAML assertion's short Conditions/notOnOrAfter window so long-running flows (e.g. multi-step booking tunnels) are not re-prompted mid-session. Assertion freshness is still enforced at login time."
  type        = number
  default     = 8

  validation {
    condition     = var.session_duration_hours > 0 && var.session_duration_hours <= 24
    error_message = "session_duration_hours must be between 1 and 24."
  }
}

variable "bypass_headers" {
  description = "Request headers letting a request through the protect Lambda without an SSO session, as { name = value }. Only for headers the viewer cannot forge, typically an x-amzn-waf-* header inserted by a WAF rule on an ACL that also blocks client-supplied x-amzn-waf-* headers: anywhere else, sending the header would skip the SSO."
  type        = map(string)
  default     = {}

  validation {
    condition     = alltrue([for name in keys(var.bypass_headers) : name == lower(name)])
    error_message = "bypass_headers names must be lowercase: CloudFront hands Lambda@Edge lowercased header keys."
  }
}

variable "cookie_domain" {
  description = "Domain of the session cookie, with its leading dot (e.g. \".preprod.example.com\"): one login then covers every protected host under it. Empty keeps a host-only cookie. Every host under the domain receives the cookie, protected or not."
  type        = string
  default     = ""

  validation {
    condition     = var.cookie_domain == "" || can(regex("^\\.[a-z0-9-]+(\\.[a-z0-9-]+)+$", var.cookie_domain))
    error_message = "cookie_domain must be empty or a lowercase domain with a leading dot, e.g. \".preprod.example.com\"."
  }
}

variable "auth_host" {
  description = "Single host whose /saml/acs receives every assertion, so the Identity Center application needs one ACS URL whatever the number of protected hosts. Requires cookie_domain, and must sit under it and serve the /saml/* behaviors. Empty keeps the ACS on each requesting host (one ACS URL per host)."
  type        = string
  default     = ""

  validation {
    condition     = var.auth_host == "" || (var.cookie_domain != "" && endswith(var.auth_host, var.cookie_domain))
    error_message = "auth_host requires cookie_domain and must be a host under it."
  }
}
