#!/usr/bin/env bash
# Patch 3: add a "gate" check that verifies target_component_or_flow in each
# threat actually refers to a real component/flow ID from the input SystemModel,
# instead of trusting the model's own output at face value.
#
# Run from the repo root:
#   chmod +x apply_patch3.sh
#   ./apply_patch3.sh
#
# Safe to run even if patches 1/2 are already applied — this only touches
# _validate_and_enrich() and its call site in analyze().

set -euo pipefail

if [ ! -f "threat_model_agent/stride_engine.py" ]; then
  echo "ERROR: run this script from the repo root (threat_model_agent/ not found here)." >&2
  exit 1
fi

echo "==> Backing up current stride_engine.py to ./patch_backups/"
mkdir -p patch_backups
cp threat_model_agent/stride_engine.py patch_backups/stride_engine.py.bak.$(date +%s)

python3 - << 'PYEOF'
import re

path = "threat_model_agent/stride_engine.py"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

old_method = '''    def _validate_and_enrich(self, data: Dict[str, Any]) -> None:
        for threat in data.get("threats", []):
            technique_ids = threat.get("attack_techniques", []) or []
            valid_ids = [t for t in technique_ids if self.attack_mapper.is_valid(t)]
            invalid_ids = [t for t in technique_ids if t not in valid_ids]
            threat["attack_techniques"] = valid_ids
            if invalid_ids:
                note = f"(removed unverified technique IDs: {', '.join(invalid_ids)})"
                threat["mitigation"] = (threat.get("mitigation", "") + " " + note).strip()'''

new_method = '''    def _validate_and_enrich(self, data: Dict[str, Any], system: SystemModel) -> None:
        """The gate: never trust the model's own claims about what a threat
        targets or which ATT&CK techniques apply. Verify both against the
        actual input before the report is generated."""
        valid_target_ids = {c.id for c in system.components} | {f.id for f in system.data_flows}

        for threat in data.get("threats", []):
            technique_ids = threat.get("attack_techniques", []) or []
            valid_ids = [t for t in technique_ids if self.attack_mapper.is_valid(t)]
            invalid_ids = [t for t in technique_ids if t not in valid_ids]
            threat["attack_techniques"] = valid_ids

            notes = []
            if invalid_ids:
                notes.append(f"removed unverified technique IDs: {', '.join(invalid_ids)}")

            target = threat.get("target_component_or_flow", "")
            if target not in valid_target_ids:
                notes.append(
                    f"\\u26a0 target '{target}' does not match any known component/flow ID "
                    "in the input system model \\u2014 verify this threat manually"
                )

            if notes:
                threat["mitigation"] = (
                    threat.get("mitigation", "") + " (" + "; ".join(notes) + ")"
                ).strip()'''

if old_method not in content:
    raise SystemExit(
        "ERROR: could not find the expected _validate_and_enrich() body. "
        "The file may already be patched, or differs from what this script expects. "
        "Check threat_model_agent/stride_engine.py manually against patch_backups/."
    )

content = content.replace(old_method, new_method)

old_call = "        self._validate_and_enrich(data)\n        return data"
new_call = "        self._validate_and_enrich(data, system)\n        return data"

if old_call not in content:
    raise SystemExit(
        "ERROR: could not find the expected call site 'self._validate_and_enrich(data)'. "
        "Check threat_model_agent/stride_engine.py manually against patch_backups/."
    )

content = content.replace(old_call, new_call)

with open(path, "w", encoding="utf-8") as f:
    f.write(content)

print("Patched _validate_and_enrich() signature, body, and call site.")
PYEOF

echo "==> Sanity-checking that the file still imports cleanly"
python3 -c "
import ast
with open('threat_model_agent/stride_engine.py', encoding='utf-8') as f:
    ast.parse(f.read())
print('  OK: threat_model_agent/stride_engine.py')
"

echo ""
echo "==> Done. Review the diff before committing:"
echo "    git diff threat_model_agent/stride_engine.py"
echo ""
echo "If it looks right:"
echo "    git add threat_model_agent/stride_engine.py"
echo "    git commit -m 'Validate target_component_or_flow against the input system model (gate check)'"
echo "    git push"