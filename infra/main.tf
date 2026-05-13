module "startup_logger" {
  source = "../modules/logger"

  log_message = "infrastructure apply started"
  log_level   = "INFO"
}
