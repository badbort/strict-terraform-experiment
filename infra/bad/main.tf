module "startup_logger" {
  source = "../../modules/good/logger"

  log_message = "infra/bad apply started"
  log_level   = "INFO"
}

# Local module that lives OUTSIDE the allowed `modules/good/` prefix; the hard
# policy must flag it on source path alone, no matter what the module contains.
module "legacy_provisioner" {
  source = "../../modules/bad/legacy_provisioner"

  command = "echo legacy module reached"
}

resource "null_resource" "sneaky" {
  triggers = {
    note = "this is a raw resource that bypasses the module policy"
  }

  provisioner "local-exec" {
    command = "echo I should not be here"
  }
}

data "null_data_source" "lookup" {
  inputs = {
    note = "raw data source — also forbidden"
  }
}

module "external_registry" {
  source  = "registry.terraform.io/some-org/some-module/aws"
  version = "1.0.0"
}
