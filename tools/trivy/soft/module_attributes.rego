# METADATA
# title: Module attribute advisory checks
# description: >-
#   Advisory rules that verify specific module calls set sensitive attributes
#   to safe values. Each entry in `module_attribute_rules` targets a single
#   module (matched by source suffix) and a single attribute. A violation is
#   emitted whenever the attribute is explicitly set AND its value differs
#   from the declared `expected`. Unset attributes fall back to the module's
#   own default and never trigger a finding.
#
#   To extend:
#     - New rule for the SAME module: append an entry with the same source_suffix.
#     - New module entirely:          append entries with a fresh source_suffix.
# scope: package
# schemas:
#   - input: schema["terraform-raw"]
# custom:
#   id: USR-MODATTR-0001
#   avd_id: USR-MODATTR-0001
#   severity: MEDIUM
#   short_code: module-attribute-policy
#   recommended_actions: "Restore the safe default, or document the exception and obtain approval."
#   input:
#     selector:
#       - type: terraform-raw

package user.terraform.module_attributes

import rego.v1

# ── Registry ────────────────────────────────────────────────────────────────
# Each rule:
#   source_suffix : tail of the `source = "..."` attribute on the module call
#                   (suffix match accommodates "../modules/good/auditor",
#                   "github.com/org/auditor", etc.)
#   attribute     : attribute name on the module call
#   message       : sprintf template; %s is replaced with the module instance name
#   AND ONE OF:
#     expected    : the value the attribute MUST equal for the rule to pass
#     forbidden   : list of values that MUST NOT appear
module_attribute_rules := [
	{
		"source_suffix": "/auditor",
		"attribute": "secure",
		"expected": true,
		"message": "auditor module '%s' has secure = false; review and approve if intentional",
	},
]

# ── Engine ──────────────────────────────────────────────────────────────────

is_root_module(module) if module.module_path == module.root_path

violates(rule, actual) if {
	expected := object.get(rule, "expected", null)
	expected != null
	actual != expected
}

violates(rule, actual) if {
	forbidden := object.get(rule, "forbidden", [])
	count(forbidden) > 0
	actual in forbidden
}

deny contains res if {
	some module in input.modules
	is_root_module(module)
	some block in module.blocks
	block.kind == "module"
	some rule in module_attribute_rules
	endswith(block.attributes.source.value, rule.source_suffix)
	actual := block.attributes[rule.attribute].value
	violates(rule, actual)
	res := result.new(
		sprintf(rule.message, [block.name]),
		block,
	)
}
