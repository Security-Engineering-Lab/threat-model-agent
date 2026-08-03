"""
CLI entry point for scanning a repository (Terraform + Django) into a
SystemModel YAML file, ready to feed into threat_model_agent.cli for
STRIDE analysis.

Usage:
    python -m threat_model_agent.scan_cli --repo /path/to/django-azure-app --output examples/scanned_system.yaml
"""
import argparse
import sys
from pathlib import Path

from .loader import load_system_model
from .scanner.model_builder import build_system_model_dict, write_system_model_yaml


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan a repo's Terraform + Django code into a SystemModel YAML")
    parser.add_argument("--repo", "-r", required=True, help="Path to the repository root")
    parser.add_argument("--output", "-o", required=True, help="Path to write the generated system model YAML")
    parser.add_argument("--name", default=None, help="Override the system name (default: repo directory name)")
    args = parser.parse_args()

    repo_root = Path(args.repo).resolve()
    if not repo_root.exists():
        print(f"Repo path does not exist: {repo_root}", file=sys.stderr)
        return 1

    model_dict = build_system_model_dict(repo_root, system_name=args.name)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    write_system_model_yaml(model_dict, output_path)

    print(f"Scanned {repo_root} -> {output_path}")
    print(f"  Components: {len(model_dict['components'])}")
    print(f"  Data flows: {len(model_dict['data_flows'])}")

    # Sanity check: make sure the generated YAML actually loads and validates
    # cleanly through the same loader the analysis CLI uses.
    try:
        load_system_model(output_path)
        print("  Validation: OK")
    except Exception as exc:
        print(f"  Validation FAILED: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
