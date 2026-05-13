from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


class NoRootResources(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Resources must be declared inside an approved module",
            id="CKV_CUSTOM_1",
            categories=(CheckCategories.GENERAL_SECURITY,),
            supported_resources=("null_resource",),
        )

    def scan_resource_conf(self, conf):
        path = (getattr(self, "entity_path", "") or "").replace("\\", "/")
        if "/modules/" in path:
            return CheckResult.PASSED
        return CheckResult.FAILED


check = NoRootResources()
