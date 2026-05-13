package main

deny contains msg if {
	some t, n
	input.resource[t][n]
	msg := sprintf("raw resource '%s.%s' is forbidden; use a module from ../modules/", [t, n])
}

deny contains msg if {
	some t, n
	input.data[t][n]
	msg := sprintf("raw data source '%s.%s' is forbidden", [t, n])
}

deny contains msg if {
	some name
	src := input.module[name][_].source
	not startswith(src, "../modules/")
	msg := sprintf("module '%s' source '%s' must be under ../modules/", [name, src])
}
