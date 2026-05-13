# METADATA
# title: Module attribute preference notices
# description: >-
#   Notice-level (LOW severity) advisory checks. Same engine and registry shape
#   as module_attributes.rego, but findings surface as SARIF level=note instead
#   of warning — the lightest tier of "we noticed something you might want to
#   look at" guidance. Suitable for rules that express team preference rather
#   than security concerns.
#
#   To extend:
#     - New rule for the SAME module: append an entry with the same source_suffix.
#     - New module entirely:          append entries with a fresh source_suffix.
# scope: package
# schemas:
#   - input: schema["terraform-raw"]
# custom:
#   id: USR-MODNOTICE-0001
#   avd_id: USR-MODNOTICE-0001
#   severity: LOW
#   short_code: module-attribute-notice
#   recommended_actions: "Consider aligning with the team default; comment-justify if you really mean it."
#   input:
#     selector:
#       - type: terraform-raw

package user.terraform.module_attributes_notice

import rego.v1

# ── Registry ────────────────────────────────────────────────────────────────
# Same schema as module_attributes.rego — rules here just live at LOW severity.
module_attribute_rules := [
	{
		"source_suffix": "/logger",
		"attribute": "log_level",
		"forbidden": ["DEBUG", "TRACE"],
		"message": "logger module '%s' uses a verbose log_level; consider raising before promoting",
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
