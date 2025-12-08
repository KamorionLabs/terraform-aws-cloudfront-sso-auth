# -----------------------------------------------------------------------------
# Identity Center SAML Application
# This module creates a custom SAML application in AWS Identity Center
# Deploy this in your management/identity account
# -----------------------------------------------------------------------------

data "aws_ssoadmin_instances" "this" {}

locals {
  instance_arn      = tolist(data.aws_ssoadmin_instances.this.arns)[0]
  identity_store_id = tolist(data.aws_ssoadmin_instances.this.identity_store_ids)[0]
}

# -----------------------------------------------------------------------------
# SAML Application
# -----------------------------------------------------------------------------
resource "aws_ssoadmin_application" "this" {
  name                     = var.application_name
  description              = var.application_description
  application_provider_arn = "arn:aws:sso::aws:applicationProvider/custom"
  instance_arn             = local.instance_arn

  portal_options {
    visibility = var.portal_visibility
    sign_in_options {
      origin          = "APPLICATION"
      application_url = var.application_start_url
    }
  }

  tags = var.tags
}

# -----------------------------------------------------------------------------
# Application Assignment (Users/Groups)
# -----------------------------------------------------------------------------
resource "aws_ssoadmin_application_assignment" "users" {
  for_each = toset(var.assigned_users)

  application_arn = aws_ssoadmin_application.this.arn
  principal_id    = each.value
  principal_type  = "USER"
}

resource "aws_ssoadmin_application_assignment" "groups" {
  for_each = toset(var.assigned_groups)

  application_arn = aws_ssoadmin_application.this.arn
  principal_id    = each.value
  principal_type  = "GROUP"
}

# -----------------------------------------------------------------------------
# Data sources to lookup users/groups by name (optional)
# -----------------------------------------------------------------------------
data "aws_identitystore_user" "by_name" {
  for_each = toset(var.assigned_user_names)

  identity_store_id = local.identity_store_id

  alternate_identifier {
    unique_attribute {
      attribute_path  = "UserName"
      attribute_value = each.value
    }
  }
}

data "aws_identitystore_group" "by_name" {
  for_each = toset(var.assigned_group_names)

  identity_store_id = local.identity_store_id

  alternate_identifier {
    unique_attribute {
      attribute_path  = "DisplayName"
      attribute_value = each.value
    }
  }
}

resource "aws_ssoadmin_application_assignment" "users_by_name" {
  for_each = data.aws_identitystore_user.by_name

  application_arn = aws_ssoadmin_application.this.arn
  principal_id    = each.value.user_id
  principal_type  = "USER"
}

resource "aws_ssoadmin_application_assignment" "groups_by_name" {
  for_each = data.aws_identitystore_group.by_name

  application_arn = aws_ssoadmin_application.this.arn
  principal_id    = each.value.group_id
  principal_type  = "GROUP"
}
