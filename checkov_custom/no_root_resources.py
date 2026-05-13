from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


# Extend the policy by adding entries to this list - no rule logic changes required.
# Checkov's `entity_path` is a string like "/path/to/file.tf:resource_type:name",
# so we substring-match (not prefix-match) anywhere in that path.
ALLOWED_PATH_SUBSTRINGS = ("/modules/", "/approved-modules/")


class NoRootResources(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Resources must be declared inside an approved module",
            id="CKV_CUSTOM_1",
            categories=(CheckCategories.GENERAL_SECURITY,),
            supported_resources=("null_resource",),
        )

    def _is_under_allowed_path(self, path: str) -> bool:
        return any(allowed in path for allowed in ALLOWED_PATH_SUBSTRINGS)

    def scan_resource_conf(self, conf):
        path = (getattr(self, "entity_path", "") or "").replace("\\", "/")
        if self._is_under_allowed_path(path):
            return CheckResult.PASSED
        return CheckResult.FAILED


check = NoRootResources()
