terraform {
  required_version = ">= 1.15.0"

  required_providers {
    null = {
      source  = "hashicorp/null"
      version = "~> 3.3"
    }
  }
}

resource "null_resource" "logger" {
  count = var.enabled ? 1 : 0

  triggers = {
    message   = var.log_message
    log_level = var.log_level
  }

  provisioner "local-exec" {
    command = "echo [${var.log_level}] ${var.log_message}"
  }
}
