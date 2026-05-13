output "resource_id" {
  description = "Id of the underlying null_resource, or null when disabled."
  value       = try(null_resource.logger[0].id, null)
}
