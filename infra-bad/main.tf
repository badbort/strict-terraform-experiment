module "startup_logger" {
  source = "../modules/logger"

  log_message = "infra-bad apply started"
  log_level   = "INFO"
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

module "external_local_escape" {
  source = "../some-untracked-dir"
}
