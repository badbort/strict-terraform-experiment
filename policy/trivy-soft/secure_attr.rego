# METADATA
# title: Module 'secure' attribute should not be set to false
# description: >-
#   Modules under our approved-modules/ tree expose a `secure` bool that defaults to true.
#   Setting it to false is permitted (some workloads need relaxed integrity checks) but
#   must be reviewed. This advisory check surfaces every secure = false invocation as a
#   GitHub code-scanning annotation; it does not block CI on its own.
# scope: package
# schemas:
#   - input: schema["terraform-raw"]
# custom:
#   id: USR-SECURE-0001
#   avd_id: USR-SECURE-0001
#   severity: MEDIUM
#   short_code: module-secure-attr
#   recommended_actions: "Set secure = true on the module call, or document the exception and obtain approval."
#   input:
#     selector:
#       - type: terraform-raw

package user.terraform.secure_attrs

import rego.v1

is_root_module(module) if module.module_path == module.root_path

deny contains res if {
	some module in input.modules
	is_root_module(module)
	some block in module.blocks
	block.kind == "module"
	block.attributes.secure.value == false
	res := result.new(
		sprintf(
			"module '%s' sets secure = false; review and approve if intentional",
			[block.name],
		),
		block,
	)
}
