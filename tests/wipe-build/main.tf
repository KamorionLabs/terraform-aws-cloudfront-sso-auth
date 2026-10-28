# Test helper: removes every instance build directory, as on a fresh checkout
# (CI runner) where only the sources exist.
resource "terraform_data" "wipe" {
  triggers_replace = timestamp()

  provisioner "local-exec" {
    command = "rm -rf '${path.module}/../../lambda/.build'"
  }
}
