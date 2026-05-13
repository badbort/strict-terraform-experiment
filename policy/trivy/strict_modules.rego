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

deny contains res if {
	keys := object.keys(input)
	res := result.new(
		sprintf("DEBUG: input top-level keys = %v", [keys]),
		input,
	)
}

deny contains res if {
	some module in input.modules
	mkeys := object.keys(module)
	res := result.new(
		sprintf("DEBUG: module keys = %v", [mkeys]),
		module,
	)
}

deny contains res if {
	some module in input.modules
	some block in module.blocks
	res := result.new(
		sprintf("DEBUG block kind=%v type=%v name=%v", [block.kind, block.type, block.name]),
		block,
	)
}

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
