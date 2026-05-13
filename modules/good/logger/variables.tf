variable "log_message" {
  description = "Message to emit when the resource is created or updated."
  type        = string
}

variable "log_level" {
  description = "Severity tag for the emitted log line."
  type        = string
  default     = "INFO"

  validation {
    condition     = contains(["DEBUG", "INFO", "WARN", "ERROR"], var.log_level)
    error_message = "log_level must be one of DEBUG, INFO, WARN, ERROR."
  }
}

variable "enabled" {
  description = "Whether the logger resource should be created."
  type        = bool
  default     = true
}
