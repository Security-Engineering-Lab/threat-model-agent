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

    def analyze(self, system: SystemModel, max_tokens: int = 4096) -> Dict[str, Any]:
        response = self.client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            system=self._build_system_prompt(),
            messages=[{"role": "user", "content": self._build_user_prompt(system)}],
        )

        text = "".join(block.text for block in response.content if block.type == "text").strip()

        if text.startswith("```"):
            text = text.strip("`")
            if text.lower().startswith("json"):
                text = text[4:]
            text = text.strip()

        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Model did not return valid JSON. Raw response:\n{text}"
            ) from exc

        self._validate_and_enrich(data)
        return data
