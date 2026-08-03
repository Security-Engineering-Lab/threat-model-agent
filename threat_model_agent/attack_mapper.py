"""
Loads the curated MITRE ATT&CK technique set and provides lookup /
validation helpers so the LLM can only reference techniques that
actually exist in the knowledge base (no hallucinated technique IDs).
"""
import json
from pathlib import Path
from typing import Dict, List, Optional

DEFAULT_DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "mitre_attack_techniques.json"


class AttackMapper:
    def __init__(self, data_path: Optional[Path] = None):
        path = Path(data_path) if data_path else DEFAULT_DATA_PATH
        with open(path, "r", encoding="utf-8") as f:
            self.techniques: List[dict] = json.load(f)
        self._by_id = {t["id"]: t for t in self.techniques}

    def get(self, technique_id: str) -> Optional[dict]:
        return self._by_id.get(technique_id)

    def is_valid(self, technique_id: str) -> bool:
        return technique_id in self._by_id

    def by_tactic(self, tactic: str) -> List[dict]:
        return [t for t in self.techniques if tactic in t.get("tactics", [])]

    def all_ids(self) -> List[str]:
        return list(self._by_id.keys())

    def summary_for_prompt(self) -> str:
        """Compact single-line-per-technique listing for the LLM prompt."""
        lines = []
        for t in self.techniques:
            lines.append(f"{t['id']} | {t['name']} | tactics: {', '.join(t['tactics'])}")
        return "\n".join(lines)

    def coverage_matrix(self, referenced_ids: List[str]) -> Dict[str, dict]:
        """Full matrix of all known techniques, flagged by whether the
        threat model actually referenced them. Useful for a gap view,
        mirroring the ATT&CK coverage matrix pattern."""
        referenced = set(referenced_ids)
        matrix = {}
        for t in self.techniques:
            matrix[t["id"]] = {
                "name": t["name"],
                "tactics": t["tactics"],
                "referenced": t["id"] in referenced,
            }
        return matrix
