package main

# Allowed module source prefixes are injected via `conftest test --data allowed.json`.
# allowed.json shape: {"allowed":{"module_sources":["../modules/","../shared-modules/"]}}

allowed_sources := data.allowed.module_sources

deny contains msg if {
	some t, n
	input.resource[t][n]
	msg := sprintf("raw resource '%s.%s' is forbidden; use an approved module (allowed sources: %v)", [t, n, allowed_sources])
}

deny contains msg if {
	some t, n
	input.data[t][n]
	msg := sprintf("raw data source '%s.%s' is forbidden", [t, n])
}

deny contains msg if {
	some name
	src := input.module[name][_].source
	not source_is_allowed(src)
	msg := sprintf("module '%s' source '%s' must start with one of %v", [name, src, allowed_sources])
}

source_is_allowed(src) if {
	some prefix in allowed_sources
	startswith(src, prefix)
}
