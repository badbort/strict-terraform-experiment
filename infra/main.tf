module "startup_logger" {
  source = "../modules/good/logger"

  log_message = "infrastructure apply started"
  log_level   = "INFO"
}

module "boot_auditor" {
  source = "../modules/good/auditor"

  event_name = "infrastructure boot"
  severity   = "INFO"
}

module "boot_auditor_relaxed" {
  source = "../modules/good/auditor"

  event_name = "infrastructure boot (relaxed)"
  severity   = "INFO"
  secure     = false
}
