# METADATA
# title: Only approved modules allowed
# description: Top-level resources are forbidden; module sources must be local under ../modules/
# scope: package
# schemas:
#   - input: schema["input"]
# custom:
#   id: STRICT_MOD_001
#   avd_id: AVD-CUSTOM-0001
#   severity: HIGH
#   short_code: strict-modules
#   recommended_action: Move the resource into a module under ./modules/ and reference it via a module block.
#   input:
#     selector:
#       - type: terraform-raw
package user.terraform.strict_modules

deny contains res if {
	some t, n
	resource := input.resource[t][n]
	msg := sprintf("raw resource '%s.%s' is forbidden; use a module from ../modules/", [t, n])
	res := result.new(msg, resource)
}

deny contains res if {
	some t, n
	d := input.data[t][n]
	msg := sprintf("raw data source '%s.%s' is forbidden", [t, n])
	res := result.new(msg, d)
}

deny contains res if {
	some name
	mod := input.module[name][_]
	not startswith(mod.source, "../modules/")
	msg := sprintf("module '%s' source '%s' must be under ../modules/", [name, mod.source])
	res := result.new(msg, mod)
}
