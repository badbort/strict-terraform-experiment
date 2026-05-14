# METADATA
# title: Only approved modules allowed
# description: Top-level resources are forbidden; module sources must be local under an allowed prefix.
# scope: package
# schemas:
#   - input: schema["terraform-raw"]
# custom:
#   id: USR-STRICT-0001
#   avd_id: USR-STRICT-0001
#   severity: HIGH
#   short_code: strict-modules
#   recommended_actions: "Move the resource into a module under an allowed prefix and reference it via a module block."
#   input:
#     selector:
#       - type: terraform-raw

package user.terraform.strict_modules

import rego.v1

# Extend the policy by adding entries to this list - no rule logic changes required.
allowed_module_prefixes := ["../../modules/good/"]

is_allowed(src) if {
	some p in allowed_module_prefixes
	startswith(src, p)
}

is_root_module(module) if module.module_path == module.root_path

deny contains res if {
	some module in input.modules
	is_root_module(module)
	some block in module.blocks
	block.kind == "resource"
	res := result.new(
		sprintf(
			"raw resource '%s.%s' is forbidden; use a module from one of: %s",
			[block.type, block.name, concat(", ", allowed_module_prefixes)],
		),
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
	not is_allowed(src)
	res := result.new(
		sprintf(
			"module '%s' source '%s' must be under one of: %s",
			[block.name, src, concat(", ", allowed_module_prefixes)],
		),
		block,
	)
}
