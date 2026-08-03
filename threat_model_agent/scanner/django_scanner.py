"""
Lightweight Django settings.py / urls.py scanner. Regex-based (no Django
import needed, so it works without installing the project's own
dependencies) — pulls out just enough to enrich the generated system model:
middleware stack, auth backends, and top-level URL prefixes.
"""
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class DjangoScanResult:
    middleware: List[str] = field(default_factory=list)
    auth_backends: List[str] = field(default_factory=list)
    installed_apps: List[str] = field(default_factory=list)
    url_prefixes: List[str] = field(default_factory=list)


def _extract_list_block(text: str, list_name: str) -> List[str]:
    m = re.search(rf"{list_name}\s*=\s*\[(.*?)\n\]", text, re.DOTALL)
    if not m:
        return []
    body = m.group(1)
    items = []
    for single, double in re.findall(r"'([^']+)'|\"([^\"]+)\"", body):
        value = (single or double).strip()
        if value:
            items.append(value)
    return items


def scan_settings(settings_path: Path) -> DjangoScanResult:
    text = Path(settings_path).read_text(encoding="utf-8", errors="ignore")
    return DjangoScanResult(
        middleware=_extract_list_block(text, "MIDDLEWARE"),
        auth_backends=_extract_list_block(text, "AUTHENTICATION_BACKENDS"),
        installed_apps=_extract_list_block(text, "INSTALLED_APPS"),
    )


def scan_urls(urls_paths: List[Path]) -> List[str]:
    """Pulls top-level path()/re_path() prefixes across one or more urls.py
    files, just to give the LLM a sense of the app's attack surface."""
    prefixes = []
    for path in urls_paths:
        if not Path(path).exists():
            continue
        text = Path(path).read_text(encoding="utf-8", errors="ignore")
        for m in re.finditer(r"(?:path|re_path)\(\s*['\"]([^'\"]*)['\"]", text):
            prefix = m.group(1)
            if prefix and prefix not in prefixes:
                prefixes.append(prefix)
    return prefixes


def find_django_files(repo_root: Path) -> "tuple[Optional[Path], List[Path]]":
    """Best-effort discovery of settings.py and all urls.py files in a repo."""
    repo_root = Path(repo_root)
    settings_candidates = list(repo_root.rglob("settings.py"))
    settings_path = settings_candidates[0] if settings_candidates else None
    urls_paths = [p for p in repo_root.rglob("urls.py") if ".venv" not in p.parts]
    return settings_path, urls_paths
