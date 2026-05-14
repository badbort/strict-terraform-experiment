"""Soft per-module attribute policy for Checkov — NOTICE tier.

Same engine and registry shape as module_attributes.py, but the workflow's
SARIF post-process step rewrites this check's level to `note` so it surfaces
in code scanning as a notice rather than a warning. Use for team preferences
that don't merit a warning.
"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.module.base_module_check import BaseModuleCheck


MODULE_ATTRIBUTE_NOTICE_RULES = [
    {
        "source_suffix": "/logger",
        "attribute": "log_level",
        "forbidden": ["DEBUG", "TRACE"],
        "message": "logger module uses a verbose log_level; consider raising before promoting",
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


class ModuleAttributePreferences(BaseModuleCheck):
    def __init__(self):
        super().__init__(
            name="Module attribute preferences (notice)",
            id="CKV_NOTICE_MODULE_ATTRS",
            categories=(CheckCategories.GENERAL_SECURITY,),
            supported_resources=("module",),
        )

    def scan_module_conf(self, conf):
        source = _first(conf, "source", "")
        for rule in MODULE_ATTRIBUTE_NOTICE_RULES:
            if not str(source).endswith(rule["source_suffix"]):
                continue
            actual = _first(conf, rule["attribute"])
            if actual is None:
                continue
            if _violates(rule, actual):
                return CheckResult.FAILED
        return CheckResult.PASSED


check = ModuleAttributePreferences()
