terraform {
  required_version = ">= 1.15.0"

  required_providers {
    null = {
      source  = "hashicorp/null"
      version = "~> 3.3"
    }
  }
}

# Deliberately under `modules/bad/` so the strict policies treat it as an
# unapproved source. The contents are otherwise unremarkable — the violation
# is the location, not the code.
resource "null_resource" "legacy" {
  triggers = {
    command = var.command
  }

  provisioner "local-exec" {
    command = var.command
  }
}
