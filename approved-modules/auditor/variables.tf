variable "event_name" {
  description = "Short label for the audit event emitted at apply time."
  type        = string
}

variable "severity" {
  description = "Severity tag for the audit line."
  type        = string
  default     = "INFO"

  validation {
    condition     = contains(["DEBUG", "INFO", "WARN", "ERROR"], var.severity)
    error_message = "severity must be one of DEBUG, INFO, WARN, ERROR."
  }
}
