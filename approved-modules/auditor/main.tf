terraform {
  required_version = ">= 1.15.0"

  required_providers {
    null = {
      source  = "hashicorp/null"
      version = "~> 3.3"
    }
  }
}

resource "null_resource" "audit" {
  triggers = {
    event    = var.event_name
    severity = var.severity
  }

  provisioner "local-exec" {
    command = "echo AUDIT [${var.severity}] ${var.event_name}"
  }
}
