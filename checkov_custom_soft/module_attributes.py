"""Soft (advisory) per-module attribute policy for Checkov.

Mirrors the shape of policy/trivy-soft/module_attributes.rego so both tools
read from a single registry concept. The check fires per *module call* in the
root module and emits one Checkov finding per module that violates any rule.
"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.module.base_module_check import BaseModuleCheck


# Registry — extend by appending entries.
#   source_suffix : tail of the module's `source = "..."` value to match
#                   (e.g. "/auditor" matches both "../approved-modules/auditor"
#                   and "github.com/org/auditor")
#   attribute     : attribute name on the module call to inspect
#   expected      : the safe value; the rule fires when the attribute is set
#                   to anything else (unset attributes default in the module
#                   and never trigger a finding)
#   message       : explanatory string surfaced in SARIF
MODULE_ATTRIBUTE_RULES = [
    {
        "source_suffix": "/auditor",
        "attribute": "secure",
        "expected": True,
        "message": "auditor module has secure = false; review and approve if intentional",
    },
    # Examples — uncomment / adapt:
    # {
    #     "source_suffix": "/auditor",
    #     "attribute":     "severity",
    #     "expected":      "INFO",
    #     "message":       "auditor module uses a non-INFO severity",
    # },
    # {
    #     "source_suffix": "/logger",
    #     "attribute":     "log_level",
    #     "expected":      "INFO",
    #     "message":       "logger module uses a non-INFO log_level",
    # },
]


def _first(conf, key, default=None):
    value = conf.get(key)
    if isinstance(value, list) and value:
        return value[0]
    if value is None:
        return default
    return value


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
            if actual != rule["expected"]:
                self.details = [rule["message"]]
                return CheckResult.FAILED
        return CheckResult.PASSED


check = ModuleAttributePolicy()
