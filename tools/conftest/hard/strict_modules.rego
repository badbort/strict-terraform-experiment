package main

# Extend the policy by adding entries to this list - no rule logic changes required.
allowed_module_prefixes := ["../../modules/good/"]

is_allowed(src) if {
	some p in allowed_module_prefixes
	startswith(src, p)
}

deny contains msg if {
	some t, n
	input.resource[t][n]
	msg := sprintf(
		"raw resource '%s.%s' is forbidden; use a module from one of: %s",
		[t, n, concat(", ", allowed_module_prefixes)],
	)
}

deny contains msg if {
	some t, n
	input.data[t][n]
	msg := sprintf("raw data source '%s.%s' is forbidden", [t, n])
}

deny contains msg if {
	some name
	src := input.module[name][_].source
	not is_allowed(src)
	msg := sprintf(
		"module '%s' source '%s' must be under one of: %s",
		[name, src, concat(", ", allowed_module_prefixes)],
	)
}
