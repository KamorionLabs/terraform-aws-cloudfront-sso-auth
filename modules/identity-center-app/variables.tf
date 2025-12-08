# -----------------------------------------------------------------------------
# Required Variables
# -----------------------------------------------------------------------------

variable "application_name" {
  description = "Display name for the Identity Center application"
  type        = string
}

variable "application_start_url" {
  description = "Start URL for the application (e.g., https://app.example.com)"
  type        = string
}

# -----------------------------------------------------------------------------
# Optional Variables
# -----------------------------------------------------------------------------

variable "application_description" {
  description = "Description for the Identity Center application"
  type        = string
  default     = "CloudFront SSO protected application"
}

variable "portal_visibility" {
  description = "Whether the application is visible in the SSO portal. Valid values: ENABLED, DISABLED"
  type        = string
  default     = "ENABLED"
}

# Assignment by ID
variable "assigned_users" {
  description = "List of user IDs to assign to this application"
  type        = list(string)
  default     = []
}

variable "assigned_groups" {
  description = "List of group IDs to assign to this application"
  type        = list(string)
  default     = []
}

# Assignment by name (convenience)
variable "assigned_user_names" {
  description = "List of usernames to assign to this application (will lookup user IDs)"
  type        = list(string)
  default     = []
}

variable "assigned_group_names" {
  description = "List of group names to assign to this application (will lookup group IDs)"
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Tags to apply to the application"
  type        = map(string)
  default     = {}
}
