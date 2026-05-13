# METADATA
# title: Only approved modules allowed
# description: Top-level resources are forbidden; module sources must be local under ../modules/
# scope: package
# schemas:
#   - input: schema["terraform-raw"]
# custom:
#   id: USR-STRICT-0001
#   avd_id: USR-STRICT-0001
#   severity: HIGH
#   short_code: strict-modules
#   recommended_actions: "Move the resource into a module under ./modules/ and reference it via a module block."
#   input:
#     selector:
#       - type: terraform-raw

package user.terraform.strict_modules

import rego.v1

# DEBUG: trigger compile error to learn module schema
_probe := input.modules[_].PROBE_FIELDS

deny contains res if {
	some module in input.modules
	some block in module.blocks
	block.kind == "resource"
	res := result.new(
		sprintf("raw resource '%s.%s' is forbidden; use a module from ../modules/", [block.type, block.name]),
		block,
	)
}

deny contains res if {
	some module in input.modules
	some block in module.blocks
	block.kind == "data"
	res := result.new(
		sprintf("raw data source '%s.%s' is forbidden", [block.type, block.name]),
		block,
	)
}

deny contains res if {
	some module in input.modules
	some block in module.blocks
	block.kind == "module"
	src := block.attributes.source.value
	not startswith(src, "../modules/")
	res := result.new(
		sprintf("module '%s' source '%s' must be under ../modules/", [block.name, src]),
		block,
	)
}
