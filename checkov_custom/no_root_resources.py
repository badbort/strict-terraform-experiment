import sys

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
        path_attrs = {
            attr: getattr(self, attr, "<missing>")
            for attr in ("file_abs_path", "file_path", "entity_path", "_file_path", "path")
        }
        conf_meta = {k: conf.get(k) for k in conf if k.startswith("__")} if isinstance(conf, dict) else {}
        print(
            f"DEBUG CKV_CUSTOM_1 fire: attrs={path_attrs} conf_meta={conf_meta}",
            file=sys.stderr,
            flush=True,
        )
        path = (getattr(self, "file_abs_path", "") or "").replace("\\", "/")
        if "/modules/" in path:
            return CheckResult.PASSED
        return CheckResult.FAILED


check = NoRootResources()
