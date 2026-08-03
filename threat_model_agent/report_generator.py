"""
Renders the STRIDE analysis result (from stride_engine.analyze) into a
Markdown threat model report, including a MITRE ATT&CK coverage matrix.
"""
from datetime import datetime, timezone
from typing import Any, Dict

from .attack_mapper import AttackMapper
from .models import SystemModel

RISK_ORDER = {"Low": 0, "Medium": 1, "High": 2}


def _risk_score(threat: Dict[str, Any]) -> int:
    return RISK_ORDER.get(threat.get("likelihood", "Low"), 0) + RISK_ORDER.get(
        threat.get("impact", "Low"), 0
    )


def generate_markdown_report(
    system: SystemModel,
    analysis: Dict[str, Any],
    attack_mapper: AttackMapper,
) -> str:
    threats = sorted(analysis.get("threats", []), key=_risk_score, reverse=True)
    referenced_ids = [tid for t in threats for tid in t.get("attack_techniques", [])]

    lines = []
    lines.append(f"# Threat Model: {system.name}")
    lines.append("")
    lines.append(f"_Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}_")
    lines.append("")
    lines.append(f"> {system.description}")
    lines.append("")

    lines.append("## Executive Summary")
    lines.append("")
    lines.append(analysis.get("executive_summary", "_No summary provided._"))
    lines.append("")

    lines.append("## System Overview")
    lines.append("")
    lines.append(f"- Components: {len(system.components)}")
    lines.append(f"- Data flows: {len(system.data_flows)}")
    lines.append(f"- Trust boundaries: {len(system.trust_boundaries)}")
    lines.append(f"- Threats identified: {len(threats)}")
    lines.append("")

    lines.append("## Threats (sorted by risk: likelihood + impact)")
    lines.append("")
    lines.append("| ID | STRIDE | Target | Title | Likelihood | Impact | ATT&CK |")
    lines.append("|---|---|---|---|---|---|---|")
    for t in threats:
        attack_str = ", ".join(t.get("attack_techniques", [])) or "-"
        lines.append(
            f"| {t.get('id','?')} | {t.get('stride_category','?')} | "
            f"{t.get('target_component_or_flow','?')} | {t.get('title','?')} | "
            f"{t.get('likelihood','?')} | {t.get('impact','?')} | {attack_str} |"
        )
    lines.append("")

    lines.append("## Threat Details & Mitigations")
    lines.append("")
    for t in threats:
        lines.append(f"### {t.get('id','?')} — {t.get('title','Untitled threat')}")
        lines.append("")
        lines.append(f"- **STRIDE category:** {t.get('stride_category','?')}")
        lines.append(f"- **Target:** {t.get('target_component_or_flow','?')}")
        lines.append(f"- **Likelihood / Impact:** {t.get('likelihood','?')} / {t.get('impact','?')}")
        attack_ids = t.get("attack_techniques", [])
        if attack_ids:
            names = []
            for tid in attack_ids:
                info = attack_mapper.get(tid)
                names.append(f"{tid} ({info['name']})" if info else tid)
            lines.append(f"- **MITRE ATT&CK:** {', '.join(names)}")
        lines.append("")
        lines.append(t.get("description", ""))
        lines.append("")
        lines.append(f"**Mitigation:** {t.get('mitigation', '_none provided_')}")
        lines.append("")

    lines.append("## MITRE ATT&CK Coverage Matrix")
    lines.append("")
    lines.append("Techniques referenced by this threat model vs. the full known set:")
    lines.append("")
    lines.append("| Technique | Name | Tactics | Referenced |")
    lines.append("|---|---|---|---|")
    matrix = attack_mapper.coverage_matrix(referenced_ids)
    for tid, info in matrix.items():
        mark = "✅" if info["referenced"] else "—"
        lines.append(f"| {tid} | {info['name']} | {', '.join(info['tactics'])} | {mark} |")
    lines.append("")

    covered = sum(1 for info in matrix.values() if info["referenced"])
    lines.append(f"**Coverage: {covered}/{len(matrix)} known techniques referenced in this model.**")
    lines.append("")

    return "\n".join(lines)
