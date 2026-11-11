# static_asset_extensions reaches the sso-check CloudFront Function: the
# sentinel in functions/sso-check.js is replaced together with its default
# list, so an edit of one without the other fails here instead of silently
# keeping the default passthrough.
# Needs Node.js, npm and python3 (the apply builds the package): the function
# embeds the HMAC key, unknown until then.
mock_provider "aws" {
  mock_resource "aws_iam_role" {
    defaults = {
      arn = "arn:aws:iam::123456789012:role/static-assets-test"
    }
  }
}

mock_provider "aws" {
  alias = "us_east_1"
}

variables {
  name          = "static-assets-test"
  saml_audience = "urn:amazon:webservices:test"
  idp_metadata  = "<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"test\"></EntityDescriptor>"
}

run "rejects_a_pattern" {
  command = plan

  variables {
    static_asset_extensions = ["css", ".*"]
  }

  expect_failures = [var.static_asset_extensions]
}

run "narrowed_list" {
  command = apply

  variables {
    static_asset_extensions = ["woff2", "ttf"]
  }

  assert {
    condition     = !strcontains(nonsensitive(local.sso_check_library_js), "__SSO_")
    error_message = "A sentinel of functions/sso-check.js was not replaced."
  }

  assert {
    condition     = strcontains(nonsensitive(local.sso_check_library_js), "var EXT = \"woff2|ttf\";")
    error_message = "static_asset_extensions does not reach the sso-check function: its sentinel or default list in functions/sso-check.js differs from main.tf."
  }
}
