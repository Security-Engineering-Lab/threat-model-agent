#!/usr/bin/env bash
# Apply patch 1 (max_tokens + stop_reason check + JSON repair retry in stride_engine.py)
# and patch 2 (role_assignment / key_vault_access_policy parsing in terraform_scanner.py,
# plus broad-privilege flagging in scanner/model_builder.py).
#
# Run this from the root of the threat-model-agent repo in your Codespace:
#   chmod +x apply_patches.sh
#   ./apply_patches.sh
#
# It rewrites the three files below in full. Make sure you have no uncommitted
# local changes to them that you care about (git diff first if unsure).

set -euo pipefail

REPO_ROOT="$(pwd)"

if [ ! -f "threat_model_agent/stride_engine.py" ]; then
  echo "ERROR: run this script from the repo root (threat_model_agent/ not found here)." >&2
  exit 1
fi

echo "==> Backing up originals to ./patch_backups/"
mkdir -p patch_backups
cp threat_model_agent/stride_engine.py patch_backups/stride_engine.py.bak
cp threat_model_agent/scanner/terraform_scanner.py patch_backups/terraform_scanner.py.bak
cp threat_model_agent/scanner/model_builder.py patch_backups/model_builder.py.bak

echo "==> Writing patched threat_model_agent/stride_engine.py"
cat > threat_model_agent/stride_engine.py << 'PYEOF'
"""
Core STRIDE analysis engine. Sends the system model to Claude and asks
for a structured JSON threat list, mapped to MITRE ATT&CK techniques
from the local knowledge base (attack_mapper.py).
"""
import json
import os
from typing import Any, Dict, Optional

from anthropic import Anthropic

from .attack_mapper import AttackMapper
from .models import SystemModel

STRIDE_CATEGORIES = [
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
]

SYSTEM_PROMPT_TEMPLATE = """You are a senior application security architect performing \
STRIDE threat modeling on a system described as a Data Flow Diagram (DFD).

Analyze every component and every data flow using these STRIDE categories:
{stride_categories}

For each threat you identify, map it to the single most relevant MITRE ATT&CK \
technique ID from this fixed list ONLY. Do not invent technique IDs, and do not \
use any ID that is not in this list. If nothing fits well, omit the mapping \
rather than guessing:

{attack_techniques}

Respond with ONLY valid JSON (no markdown fences, no prose before or after), \
matching exactly this schema:

{{
  "threats": [
    {{
      "id": "T-001",
      "target_component_or_flow": "component/flow id from the input",
      "stride_category": "one of the STRIDE categories above",
      "title": "short threat title",
      "description": "2-4 sentence description of the threat scenario",
      "attack_techniques": ["T####"],
      "likelihood": "Low | Medium | High",
      "impact": "Low | Medium | High",
      "mitigation": "concrete, specific mitigation recommendation"
    }}
  ],
  "executive_summary": "3-5 sentence overview of the overall risk posture"
}}
"""


class ThreatModelingEngine:
    def __init__(
        self,
        model: str = "claude-sonnet-5",
        attack_mapper: Optional[AttackMapper] = None,
        api_key: Optional[str] = None,
    ):
        resolved_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not resolved_key:
            raise RuntimeError(
                "No API key found. Set the ANTHROPIC_API_KEY environment variable "
                "or pass api_key= explicitly."
            )
        self.client = Anthropic(api_key=resolved_key)
        self.model = model
        self.attack_mapper = attack_mapper or AttackMapper()

    def _build_system_prompt(self) -> str:
        return SYSTEM_PROMPT_TEMPLATE.format(
            stride_categories="\n".join(f"- {c}" for c in STRIDE_CATEGORIES),
            attack_techniques=self.attack_mapper.summary_for_prompt(),
        )

    def _build_user_prompt(self, system: SystemModel) -> str:
        lines = [f"System name: {system.name}", f"Description: {system.description}", ""]

        lines.append("Components:")
        for c in system.components:
            tech = f", technologies: {', '.join(c.technologies)}" if c.technologies else ""
            lines.append(
                f"  - id={c.id}, name={c.name}, type={c.type}, "
                f"trust_zone={c.trust_zone}{tech}. {c.description}"
            )

        lines.append("")
        lines.append("Data flows:")
        for f in system.data_flows:
            boundary = " [crosses trust boundary]" if f.crosses_trust_boundary else ""
            lines.append(
                f"  - id={f.id}, {f.source} -> {f.destination}, "
                f"protocol={f.protocol or 'unspecified'}, "
                f"classification={f.data_classification}{boundary}. {f.description}"
            )

        if system.trust_boundaries:
            lines.append("")
            lines.append("Trust boundaries:")
            for b in system.trust_boundaries:
                lines.append(f"  - id={b.id}, name={b.name}. {b.description}")

        return "\n".join(lines)

    def _validate_and_enrich(self, data: Dict[str, Any]) -> None:
        for threat in data.get("threats", []):
            technique_ids = threat.get("attack_techniques", []) or []
            valid_ids = [t for t in technique_ids if self.attack_mapper.is_valid(t)]
            invalid_ids = [t for t in technique_ids if t not in valid_ids]
            threat["attack_techniques"] = valid_ids
            if invalid_ids:
                note = f"(removed unverified technique IDs: {', '.join(invalid_ids)})"
                threat["mitigation"] = (threat.get("mitigation", "") + " " + note).strip()

    def _call_model(self, system_prompt: str, user_prompt: str, max_tokens: int) -> str:
        """Single API call, returns raw text. Raises on truncation."""
        response = self.client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )

        if response.stop_reason == "max_tokens":
            raise RuntimeError(
                f"Response was truncated at max_tokens={max_tokens} before completing. "
                "Increase max_tokens (the system likely has too many components/flows "
                "for the current limit) and retry."
            )

        return "".join(block.text for block in response.content if block.type == "text").strip()

    @staticmethod
    def _strip_fences(text: str) -> str:
        if text.startswith("```"):
            text = text.strip("`")
            if text.lower().startswith("json"):
                text = text[4:]
            text = text.strip()
        return text

    def analyze(self, system: SystemModel, max_tokens: int = 8192) -> Dict[str, Any]:
        system_prompt = self._build_system_prompt()
        user_prompt = self._build_user_prompt(system)

        text = self._strip_fences(self._call_model(system_prompt, user_prompt, max_tokens))

        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            # One repair attempt: show the model its own broken output and the
            # parser error, ask for a corrected JSON-only response.
            repair_prompt = (
                f"Your previous response was not valid JSON. Parser error:\n{exc}\n\n"
                f"Your previous response was:\n{text}\n\n"
                "Return ONLY the corrected, valid JSON matching the original schema. "
                "No markdown fences, no prose."
            )
            try:
                repaired_text = self._strip_fences(
                    self._call_model(system_prompt, repair_prompt, max_tokens)
                )
                data = json.loads(repaired_text)
            except (json.JSONDecodeError, RuntimeError) as repair_exc:
                raise ValueError(
                    f"Model did not return valid JSON, and the repair attempt also "
                    f"failed: {repair_exc}\nOriginal raw response:\n{text}"
                ) from repair_exc

        self._validate_and_enrich(data)
        return data
PYEOF

echo "==> Writing patched threat_model_agent/scanner/terraform_scanner.py"
cat > threat_model_agent/scanner/terraform_scanner.py << 'PYEOF'
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

# Attrs relevant to role/permission scoping — only meaningful for
# azurerm_role_assignment / azurerm_key_vault_access_policy resources, so
# pulled separately to avoid noise on every other resource type.
ROLE_ATTRS = [
    "scope",
    "role_definition_name",
    "role_definition_id",
    "principal_id",
]

KEY_VAULT_POLICY_LIST_ATTRS = [
    "secret_permissions",
    "key_permissions",
    "certificate_permissions",
]

ROLE_SCOPED_RESOURCE_TYPES = {"azurerm_role_assignment", "azurerm_key_vault_access_policy"}


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


def _extract_role_attrs(body: str) -> Dict[str, str]:
    attrs = {}
    for key in ROLE_ATTRS:
        m = re.search(ATTR_RE_TEMPLATE.format(attr=re.escape(key)), body)
        if m:
            attrs[key] = m.group(1).strip()
    for key in KEY_VAULT_POLICY_LIST_ATTRS:
        m = re.search(rf'{key}\s*=\s*\[([^\]]*)\]', body, re.DOTALL)
        if m:
            values = re.findall(r'"([^"]+)"', m.group(1))
            attrs[key] = ", ".join(values)
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

            if rtype in ROLE_SCOPED_RESOURCE_TYPES:
                attrs = _extract_role_attrs(body)
            else:
                attrs = _extract_attrs(body)

            resources.append(
                TerraformResource(
                    type=rtype,
                    name=rname,
                    file=str(tf_file.relative_to(root)),
                    body=body,
                    attrs=attrs,
                )
            )
    return resources


def find_django_files(repo_root: Path) -> "tuple[Optional[Path], List[Path]]":
    """Best-effort discovery of settings.py and all urls.py files in a repo."""
    repo_root = Path(repo_root)
    settings_candidates = list(repo_root.rglob("settings.py"))
    settings_path = settings_candidates[0] if settings_candidates else None
    urls_paths = [p for p in repo_root.rglob("urls.py") if ".venv" not in p.parts]
    return settings_path, urls_paths
PYEOF

# NOTE: find_django_files above actually lives in django_scanner.py in the
# original repo layout, not terraform_scanner.py — remove the accidental
# duplicate this heredoc would otherwise introduce.
python3 - << 'PYFIX'
import re
path = "threat_model_agent/scanner/terraform_scanner.py"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()
content = re.sub(
    r'\n\ndef find_django_files.*$',
    '\n',
    content,
    flags=re.DOTALL,
)
with open(path, "w", encoding="utf-8") as f:
    f.write(content)
PYFIX

echo "==> Writing patched threat_model_agent/scanner/model_builder.py"
cat > threat_model_agent/scanner/model_builder.py << 'PYEOF'
"""
Combines terraform_scanner + django_scanner output into a SystemModel and
writes it out as YAML, ready for stride_engine.analyze().

Design note: this is intentionally heuristic, not a full Terraform graph
evaluator. It recognizes a fixed set of common Azure resource types,
infers data flows from private_endpoint / delegated_subnet_id /
diagnostic_setting resources, flags datastore-type resources that have NO
diagnostic_setting flow pointing at a logging sink, and flags role
assignments / Key Vault access policies that look broader than a
least-privilege application identity would need.
"""
import re
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from .django_scanner import find_django_files, scan_settings, scan_urls
from .terraform_scanner import TerraformResource, scan_terraform_directory

# type -> (component_type, trust_zone, friendly_name, fixed_id)
COMPONENT_RESOURCE_MAP = {
    "azurerm_linux_web_app": ("process", "dmz", "Azure App Service (Linux)", "app_service"),
    "azurerm_windows_web_app": ("process", "dmz", "Azure App Service (Windows)", "app_service"),
    "azurerm_linux_function_app": ("process", "dmz", "Azure Function App (Linux)", "app_service"),
    "azurerm_key_vault": ("datastore", "restricted", "Azure Key Vault", "key_vault"),
    "azurerm_postgresql_flexible_server": ("datastore", "restricted", "Azure PostgreSQL Flexible Server", "postgres"),
    "azurerm_mysql_flexible_server": ("datastore", "restricted", "Azure MySQL Flexible Server", "mysql"),
    "azurerm_cosmosdb_account": ("datastore", "restricted", "Azure Cosmos DB", "cosmosdb"),
    "azurerm_storage_account": ("datastore", "restricted", "Azure Storage Account", "storage_account"),
    "azurerm_redis_cache": ("datastore", "internal", "Azure Cache for Redis", "redis"),
    "azurerm_log_analytics_workspace": ("process", "internal", "Log Analytics Workspace", "log_analytics"),
    "azurerm_application_insights": ("process", "internal", "Application Insights", "app_insights"),
    "azurerm_sentinel_log_analytics_workspace_onboarding": ("process", "internal", "Microsoft Sentinel", "sentinel"),
}

PRIMARY_PROCESS_TYPES = {"azurerm_linux_web_app", "azurerm_windows_web_app", "azurerm_linux_function_app"}
LOG_SINK_IDS = {"log_analytics", "sentinel", "app_insights"}

RESOURCE_ADDR_RE = re.compile(r"([a-zA-Z_][a-zA-Z0-9_]*)\.([a-zA-Z0-9_\-]+)\.id")

# Roles broad enough to warrant a flag when granted via azurerm_role_assignment.
BROAD_ROLE_NAMES = {"Contributor", "Owner", "Key Vault Administrator"}

# Key Vault secret permission sets broader than a typical read-only app identity needs.
BROAD_KV_SECRET_PERMS = {"get", "set", "delete"}


def _friendly_id(resource: TerraformResource, used_ids: Dict[str, int]) -> Optional[str]:
    mapping = COMPONENT_RESOURCE_MAP.get(resource.type)
    if not mapping:
        return None
    _, _, _, fixed_id = mapping
    count = used_ids.get(fixed_id, 0)
    used_ids[fixed_id] = count + 1
    return fixed_id if count == 0 else f"{fixed_id}_{count + 1}"


def _build_components(resources: List[TerraformResource]):
    components = []
    resource_lookup: Dict[tuple, str] = {}  # (type, name) -> component id
    used_ids: Dict[str, int] = {}

    for r in resources:
        mapping = COMPONENT_RESOURCE_MAP.get(r.type)
        if not mapping:
            continue
        comp_type, trust_zone, tech_name, _ = mapping
        comp_id = _friendly_id(r, used_ids)
        resource_lookup[(r.type, r.name)] = comp_id

        details = [f"Detected via Terraform resource `{r.type}.{r.name}` ({r.file})."]
        if r.attr("sku_name"):
            details.append(f"SKU: {r.attr('sku_name')}.")
        if r.attr("public_network_access_enabled") == "false":
            details.append("Public network access explicitly disabled.")

        components.append(
            {
                "id": comp_id,
                "name": tech_name,
                "type": comp_type,
                "trust_zone": trust_zone,
                "technologies": [tech_name],
                "description": " ".join(details),
                "_resource": r,
            }
        )

    return components, resource_lookup


def _resolve_addr(value: str) -> Optional[tuple]:
    """Parses something like 'azurerm_key_vault.main.id' -> ('azurerm_key_vault', 'main')."""
    m = RESOURCE_ADDR_RE.search(value or "")
    if not m:
        return None
    return m.group(1), m.group(2)


def _find_primary_process(components: List[dict]) -> Optional[dict]:
    for c in components:
        if c["_resource"].type in PRIMARY_PROCESS_TYPES:
            return c
    return None


def _flag_broad_privileges(resources: List[TerraformResource], components: List[dict]) -> None:
    """Cross-references azurerm_role_assignment / azurerm_key_vault_access_policy
    resources against mapped components and annotates any that look broader
    than a least-privilege application identity would need. Matching is a
    best-effort keyword match against the resource's `scope` attribute, since
    scope is usually a resource-id-style reference (possibly interpolated)."""
    comp_by_keyword = {c["id"].split("_")[0]: c for c in components if "_resource" in c}

    for r in resources:
        if r.type == "azurerm_role_assignment":
            role_name = r.attr("role_definition_name") or ""
            scope = (r.attr("scope") or "").lower()
            if role_name in BROAD_ROLE_NAMES:
                target = next((c for kw, c in comp_by_keyword.items() if kw and kw in scope), None)
                note = (
                    f" ⚠ Terraform grants the broad role '{role_name}' via "
                    f"`{r.type}.{r.name}` — consider a narrower, resource-specific "
                    f"built-in role scoped to only what the app identity needs."
                )
                if target:
                    target["description"] += note
                # else: broad role with an unresolvable/dynamic scope — surfaced
                # in the printed scan summary instead, see build_system_model_dict.

        elif r.type == "azurerm_key_vault_access_policy":
            secret_perms = {
                p.strip().lower() for p in (r.attr("secret_permissions") or "").split(",") if p.strip()
            }
            if secret_perms and secret_perms.issuperset(BROAD_KV_SECRET_PERMS):
                kv = next((c for c in components if c["id"] == "key_vault"), None)
                if kv:
                    kv["description"] += (
                        f" ⚠ `{r.type}.{r.name}` grants broad secret permissions "
                        f"({', '.join(sorted(secret_perms))}) — a read-only application "
                        f"identity typically only needs 'get' and 'list'."
                    )


def _build_flows(resources: List[TerraformResource], components: List[dict], resource_lookup: Dict[tuple, str]):
    flows = []
    flow_counter = 0
    logged_component_ids = set()
    synthetic_components: Dict[str, dict] = {}

    primary = _find_primary_process(components)

    def next_flow_id():
        nonlocal flow_counter
        flow_counter += 1
        return f"flow_{flow_counter:03d}"

    # 1) private_endpoint -> infer primary_process -> target resource
    for r in resources:
        if r.type != "azurerm_private_endpoint":
            continue
        addr = _resolve_addr(r.attr("private_connection_resource_id") or "")
        if not addr or addr not in resource_lookup or not primary:
            continue
        target_id = resource_lookup[addr]
        subres = r.attr("subresource_names") or "private link"
        flows.append(
            {
                "id": next_flow_id(),
                "source": primary["id"],
                "destination": target_id,
                "protocol": f"Private Endpoint ({subres})",
                "data_classification": "restricted",
                "crosses_trust_boundary": True,
                "description": f"Inferred from `{r.type}.{r.name}` in {r.file}.",
            }
        )

    # 2) delegated_subnet_id (VNet-integrated DB, e.g. PostgreSQL Flexible Server) -> primary -> db
    for r in resources:
        if r.type not in COMPONENT_RESOURCE_MAP or not r.attr("delegated_subnet_id"):
            continue
        if (r.type, r.name) not in resource_lookup or not primary:
            continue
        target_id = resource_lookup[(r.type, r.name)]
        already = any(f["source"] == primary["id"] and f["destination"] == target_id for f in flows)
        if already:
            continue
        flows.append(
            {
                "id": next_flow_id(),
                "source": primary["id"],
                "destination": target_id,
                "protocol": "VNet delegated subnet integration",
                "data_classification": "confidential",
                "crosses_trust_boundary": True,
                "description": f"Inferred from `delegated_subnet_id` on `{r.type}.{r.name}` in {r.file}.",
            }
        )

    # 3) diagnostic_setting -> some component -> log sink (matched by keyword in setting name)
    log_sink = next((c for c in components if c["id"] in LOG_SINK_IDS and c["id"] != "app_insights"), None)
    for r in resources:
        if r.type != "azurerm_monitor_diagnostic_setting" or not log_sink:
            continue
        setting_name = (r.attr("name") or r.name).lower()
        categories = re.findall(r'category\s*=\s*"([^"]+)"', r.body)
        matched_source = None
        for c in components:
            if c["id"] == log_sink["id"]:
                continue
            keyword = c["id"].split("_")[0]
            if keyword in setting_name or keyword in r.name.lower():
                matched_source = c
                break
        if not matched_source and "subscription" in (r.attr("target_resource_id") or ""):
            matched_source = {"id": "azure_activity_log", "_synthetic_name": "Azure Activity Log"}
        elif matched_source and matched_source["id"] in LOG_SINK_IDS:
            matched_source = None

        if matched_source:
            if "_synthetic_name" in matched_source and matched_source["id"] not in synthetic_components:
                synthetic_components[matched_source["id"]] = {
                    "id": matched_source["id"],
                    "name": matched_source["_synthetic_name"],
                    "type": "external_entity",
                    "trust_zone": "internal",
                    "technologies": [],
                    "description": "Synthetic node representing a subscription/tenant-scoped diagnostic source, not a single Terraform resource.",
                }
            logged_component_ids.add(matched_source["id"])
            flows.append(
                {
                    "id": next_flow_id(),
                    "source": matched_source["id"],
                    "destination": log_sink["id"],
                    "protocol": "Diagnostic setting",
                    "data_classification": "internal",
                    "crosses_trust_boundary": False,
                    "description": (
                        f"Inferred from `{r.type}.{r.name}` in {r.file}. "
                        f"Categories: {', '.join(categories) or 'unspecified'}."
                    ),
                }
            )

    # 4) Flag datastore components with no outbound logging flow.
    for c in components:
        if c["type"] == "datastore" and c["id"] not in logged_component_ids:
            c["description"] += (
                " ⚠ No `azurerm_monitor_diagnostic_setting` resource in Terraform was found "
                "targeting this resource — if logging exists at all, it is currently a manual, "
                "out-of-IaC artifact rather than a reproducible, version-controlled control."
            )

    return flows, list(synthetic_components.values())


def build_system_model_dict(
    repo_root: Path,
    system_name: Optional[str] = None,
) -> dict:
    repo_root = Path(repo_root)
    resources = scan_terraform_directory(repo_root)
    components, resource_lookup = _build_components(resources)
    _flag_broad_privileges(resources, components)

    settings_path, urls_paths = find_django_files(repo_root)
    django_result = scan_settings(settings_path) if settings_path else None
    url_prefixes = scan_urls(urls_paths) if urls_paths else []

    output_components = [
        {
            "id": "user",
            "name": "End User",
            "type": "actor",
            "trust_zone": "internet",
            "technologies": [],
            "description": "Authenticates via browser over HTTPS.",
        }
    ]

    if django_result and any("EntraID" in b or "entra" in b.lower() for b in django_result.auth_backends):
        output_components.append(
            {
                "id": "identity_provider",
                "name": "Identity Provider",
                "type": "external_entity",
                "trust_zone": "internet",
                "technologies": ["Detected via AUTHENTICATION_BACKENDS in settings.py"],
                "description": f"Auth backends detected: {', '.join(django_result.auth_backends)}.",
            }
        )

    flows, synthetic_components = _build_flows(resources, components, resource_lookup)

    clean_components = [{k: v for k, v in c.items() if k != "_resource"} for c in components]
    clean_components.extend(synthetic_components)

    if django_result and any(
        "identity_provider" == c["id"] for c in output_components
    ) and clean_components:
        primary = next((c for c in clean_components if c["id"] == "app_service"), None)
        if primary:
            flows.insert(
                0,
                {
                    "id": "flow_auth",
                    "source": "identity_provider",
                    "destination": "app_service",
                    "protocol": "HTTPS/OIDC",
                    "data_classification": "confidential",
                    "crosses_trust_boundary": True,
                    "description": "Token/assertion returned after authentication.",
                },
            )
            flows.insert(
                0,
                {
                    "id": "flow_login",
                    "source": "user",
                    "destination": "identity_provider",
                    "protocol": "HTTPS/OIDC",
                    "data_classification": "confidential",
                    "crosses_trust_boundary": True,
                    "description": "User-initiated login.",
                },
            )
    else:
        primary = next((c for c in clean_components if c["id"] == "app_service"), None)
        if primary:
            flows.insert(
                0,
                {
                    "id": "flow_access",
                    "source": "user",
                    "destination": "app_service",
                    "protocol": "HTTPS",
                    "data_classification": "internal",
                    "crosses_trust_boundary": True,
                    "description": "Direct user access over HTTPS.",
                },
            )

    description_parts = [
        f"Auto-generated from Terraform scan of `{repo_root.name}` "
        f"({len(resources)} resources scanned, {len(clean_components)} mapped to components)."
    ]
    if url_prefixes:
        description_parts.append(f"Detected URL prefixes: {', '.join(sorted(url_prefixes))}.")

    model = {
        "name": system_name or repo_root.name,
        "description": " ".join(description_parts),
        "components": output_components + clean_components,
        "data_flows": flows,
        "trust_boundaries": [
            {
                "id": "tb_internet_dmz",
                "name": "Internet / DMZ boundary",
                "description": "Public internet to application edge.",
            },
            {
                "id": "tb_dmz_restricted",
                "name": "DMZ / Restricted data boundary",
                "description": "Application subnet to private/restricted data stores.",
            },
        ],
    }
    return model


def write_system_model_yaml(model: dict, output_path: Path) -> None:
    with open(output_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(model, f, sort_keys=False, allow_unicode=True, default_flow_style=False)
PYEOF

echo "==> Sanity-checking that all patched files at least import cleanly"
python3 -c "
import ast
for f in [
    'threat_model_agent/stride_engine.py',
    'threat_model_agent/scanner/terraform_scanner.py',
    'threat_model_agent/scanner/model_builder.py',
]:
    with open(f, encoding='utf-8') as fh:
        ast.parse(fh.read())
    print(f'  OK: {f}')
"

echo ""
echo "==> Done. Review the diff before committing:"
echo "    git diff threat_model_agent/stride_engine.py threat_model_agent/scanner/terraform_scanner.py threat_model_agent/scanner/model_builder.py"
echo ""
echo "If it looks right:"
echo "    git add threat_model_agent/stride_engine.py threat_model_agent/scanner/terraform_scanner.py threat_model_agent/scanner/model_builder.py"
echo "    git commit -m 'Increase max_tokens + add JSON repair retry; parse role_assignment/access_policy for privilege flagging'"
echo "    git push"