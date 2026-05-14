"""Soft (advisory) per-module attribute policy for Checkov — WARNING tier.

Mirrors the shape of tools/trivy/soft/module_attributes.rego so both tools
read from a single registry concept. The check fires per *module call* in the
root module and emits one Checkov finding per module that violates any rule.

Each rule must declare ONE OF:
  expected  : the value the attribute MUST equal
  forbidden : list of values the attribute MUST NOT be
"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.module.base_module_check import BaseModuleCheck


MODULE_ATTRIBUTE_RULES = [
    {
        "source_suffix": "/auditor",
        "attribute": "secure",
        "expected": True,
        "message": "auditor module has secure = false; review and approve if intentional",
    },
]


def _first(conf, key, default=None):
    value = conf.get(key)
    if isinstance(value, list) and value:
        return value[0]
    if value is None:
        return default
    return value


def _violates(rule, actual):
    if "expected" in rule:
        return actual != rule["expected"]
    if "forbidden" in rule:
        return actual in rule["forbidden"]
    return False


class ModuleAttributePolicy(BaseModuleCheck):
    def __init__(self):
        super().__init__(
            name="Module attribute advisory checks",
            id="CKV_SOFT_MODULE_ATTRS",
            categories=(CheckCategories.GENERAL_SECURITY,),
            supported_resources=("module",),
        )

    def scan_module_conf(self, conf):
        source = _first(conf, "source", "")
        for rule in MODULE_ATTRIBUTE_RULES:
            if not str(source).endswith(rule["source_suffix"]):
                continue
            actual = _first(conf, rule["attribute"])
            if actual is None:
                continue
            if _violates(rule, actual):
                return CheckResult.FAILED
        return CheckResult.PASSED


check = ModuleAttributePolicy()
