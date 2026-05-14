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

variable "secure" {
  description = "When false, the auditor runs in relaxed mode (logging without integrity checks). Setting this to false is permitted but tracked via code-scanning annotations."
  type        = bool
  default     = true
}
