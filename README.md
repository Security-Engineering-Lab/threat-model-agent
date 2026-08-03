# Threat Model Agent

STRIDE-based threat modeling agent powered by Claude. Feed it a Data Flow
Diagram (as YAML/JSON), and it produces a structured threat model report
with threats mapped to MITRE ATT&CK techniques, risk-sorted, with concrete
mitigations.

## Installation

pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...

## Usage

python -m threat_model_agent.cli --input examples/sample_system.yaml
python -m threat_model_agent.cli --input examples/sample_system.yaml --output report.md
python -m threat_model_agent.cli --input examples/sample_system.yaml --offline-demo

## Scanning a real repository

python -m threat_model_agent.scan_cli --repo /path/to/django-azure-app --output examples/scanned_system.yaml

Recognizes Azure resource types in Terraform (App Service, Key Vault,
PostgreSQL Flexible Server, Storage Account, Log Analytics, App Insights,
Sentinel onboarding), infers data flows from private_endpoint,
delegated_subnet_id, and monitor_diagnostic_setting resources, and flags
any datastore resource with no diagnostic_setting pointing at it as a
real logging gap. Always review the generated YAML before analyzing it —
it's a heuristic first draft, not ground truth.
