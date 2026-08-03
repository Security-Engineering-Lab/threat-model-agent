"""
Lightweight Terraform (.tf) resource block scanner.

Deliberately avoids a full HCL parser dependency: Terraform written with
${...} interpolations trips up several lightweight HCL libraries (nested
braces inside string interpolations confuse them). A brace-counting
scanner over `resource "type" "name" { ... }` blocks is more robust for
this use case, since we only need resource type + a handful of top-level
attributes, not a full expression AST.
"""
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

RESOURCE_RE = re.compile(r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{')
ATTR_RE_TEMPLATE = r'{attr}\s*=\s*"?([^"\n]+?)"?\s*(?:\n|$)'


@dataclass
class TerraformResource:
    type: str
    name: str
    file: str
    body: str
    attrs: Dict[str, str] = field(default_factory=dict)

    def attr(self, key: str) -> Optional[str]:
        return self.attrs.get(key)


def _extract_block(text: str, start: int) -> str:
    """Given the position right after a resource's opening '{', return the
    matching block body using simple brace counting. Terraform interpolation
    braces (${...}) are balanced themselves, so naive counting still works."""
    depth = 1
    i = start
    while i < len(text) and depth > 0:
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
        i += 1
    return text[start : i - 1]


# A handful of simple top-level attributes worth pulling out per resource,
# used later to infer trust zones and data flows.
INTERESTING_ATTRS = [
    "name",
    "sku_name",
    "public_network_access_enabled",
    "virtual_network_subnet_id",
    "delegated_subnet_id",
    "subnet_id",
    "target_resource_id",
    "log_analytics_workspace_id",
    "private_connection_resource_id",
    "administrator_login",
]


def _extract_attrs(body: str) -> Dict[str, str]:
    attrs = {}
    for key in INTERESTING_ATTRS:
        m = re.search(ATTR_RE_TEMPLATE.format(attr=re.escape(key)), body)
        if m:
            attrs[key] = m.group(1).strip()
    # subresource_names = ["vault"] style lists (used by private endpoints)
    m = re.search(r'subresource_names\s*=\s*\[([^\]]*)\]', body)
    if m:
        attrs["subresource_names"] = m.group(1).replace('"', "").strip()
    return attrs


def scan_terraform_directory(root: Path) -> List[TerraformResource]:
    """Recursively scans all .tf files under root and returns every
    resource block found, with a few interesting attributes extracted."""
    resources: List[TerraformResource] = []
    for tf_file in sorted(Path(root).rglob("*.tf")):
        if ".terraform" in tf_file.parts:
            continue
        text = tf_file.read_text(encoding="utf-8", errors="ignore")
        for m in RESOURCE_RE.finditer(text):
            rtype, rname = m.group(1), m.group(2)
            body = _extract_block(text, m.end())
            resources.append(
                TerraformResource(
                    type=rtype,
                    name=rname,
                    file=str(tf_file.relative_to(root)),
                    body=body,
                    attrs=_extract_attrs(body),
                )
            )
    return resources
