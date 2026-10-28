# A fresh checkout must plan no change when neither the sources nor the
# configuration changed: no rebuild, no Lambda update, no new version.
# Needs Node.js, npm and python3 (the first run builds the package).
mock_provider "aws" {
  mock_resource "aws_iam_role" {
    defaults = {
      arn = "arn:aws:iam::123456789012:role/plan-noise-test"
    }
  }
}

mock_provider "aws" {
  alias = "us_east_1"
}

variables {
  name          = "plan-noise-test"
  saml_audience = "urn:amazon:webservices:test"
  idp_metadata  = "<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"test\"></EntityDescriptor>"
}

run "build" {
  command = apply
}

run "fresh_checkout" {
  module {
    source = "./tests/wipe-build"
  }
}

run "plan_without_build_directory" {
  command = plan

  # Both are unknown when the plan rebuilds the package.
  assert {
    condition     = null_resource.build_lambda.id != ""
    error_message = "The plan rebuilds the package on a fresh checkout."
  }

  assert {
    condition     = aws_lambda_function.protect.source_code_hash != ""
    error_message = "The plan updates the Lambda code on a fresh checkout."
  }
}
