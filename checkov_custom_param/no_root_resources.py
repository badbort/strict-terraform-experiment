import os

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


# The list of allowed path substrings is injected via the
# ALLOWED_MODULE_PATH_SUBSTRINGS environment variable as a comma-separated list,
# e.g. "../modules/,../shared-modules/". A resource passes the check when its
# entity_path contains at least one of those substrings (normalised to forward
# slashes so the check behaves the same on Linux and Windows).
#
# We read the env var at check time (inside scan_resource_conf) rather than at
# import time so the workflow can change the allow list per-run without
# reloading the module.


def _allowed_substrings() -> list[str]:
    raw = os.environ.get("ALLOWED_MODULE_PATH_SUBSTRINGS", "")
    return [s.strip() for s in raw.split(",") if s.strip()]


class NoRootResourcesParam(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Resources must be declared inside an approved module (parametrized)",
            id="CKV_CUSTOM_2",
            categories=(CheckCategories.GENERAL_SECURITY,),
            # NOTE: ("*",) is NOT a wildcard in Checkov; we must enumerate the
            # resource types that can legally appear in this experiment.
            supported_resources=("null_resource",),
        )

    def scan_resource_conf(self, conf):
        path = (getattr(self, "entity_path", "") or "").replace("\\", "/")
        allowed = _allowed_substrings()
        if not allowed:
            # No allow list configured -> nothing can be approved; fail closed.
            return CheckResult.FAILED
        for substring in allowed:
            if substring and substring in path:
                return CheckResult.PASSED
        return CheckResult.FAILED


check = NoRootResourcesParam()
