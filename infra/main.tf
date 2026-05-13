module "startup_logger" {
  source = "../modules/logger"

  log_message = "infrastructure apply started"
  log_level   = "INFO"
}

module "boot_auditor" {
  source = "../approved-modules/auditor"

  event_name = "infrastructure boot"
  severity   = "INFO"
}

module "boot_auditor_relaxed" {
  source = "../approved-modules/auditor"

  event_name = "infrastructure boot (relaxed)"
  severity   = "INFO"
  secure     = false
}
