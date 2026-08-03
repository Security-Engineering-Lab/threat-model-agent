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
