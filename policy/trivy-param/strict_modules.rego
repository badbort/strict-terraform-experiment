# METADATA
# title: Only approved modules allowed (parametrized)
# description: Top-level resources are forbidden; module sources must match an injected allow list.
# scope: package
# schemas:
#   - input: schema["terraform-raw"]
# custom:
#   id: USR-STRICT-0002
#   avd_id: USR-STRICT-0002
#   severity: HIGH
#   short_code: strict-modules-param
#   recommended_actions: "Move the resource into an approved module and reference it via a module block."
#   input:
#     selector:
#       - type: terraform-raw

package user.terraform.strict_modules_param

import rego.v1

# Allowed module source prefixes are injected via `trivy config --config-data allowed.json`.
# allowed.json shape: {"allowed":{"module_sources":["../modules/","../shared-modules/"]}}

allowed_sources := data.allowed.module_sources

is_root_module(module) if module.module_path == module.root_path

source_is_allowed(src) if {
	some prefix in allowed_sources
	startswith(src, prefix)
}

deny contains res if {
	some module in input.modules
	is_root_module(module)
	some block in module.blocks
	block.kind == "resource"
	res := result.new(
		sprintf("raw resource '%s.%s' is forbidden; use an approved module (allowed sources: %v)", [block.type, block.name, allowed_sources]),
		block,
	)
}

deny contains res if {
	some module in input.modules
	is_root_module(module)
	some block in module.blocks
	block.kind == "data"
	res := result.new(
		sprintf("raw data source '%s.%s' is forbidden", [block.type, block.name]),
		block,
	)
}

deny contains res if {
	some module in input.modules
	is_root_module(module)
	some block in module.blocks
	block.kind == "module"
	src := block.attributes.source.value
	not source_is_allowed(src)
	res := result.new(
		sprintf("module '%s' source '%s' must start with one of %v", [block.name, src, allowed_sources]),
		block,
	)
}
