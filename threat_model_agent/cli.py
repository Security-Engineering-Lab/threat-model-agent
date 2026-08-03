"""
CLI entry point for the threat modeling agent.

Usage:
    python -m threat_model_agent.cli --input examples/sample_system.yaml --output report.md
    python -m threat_model_agent.cli --input examples/sample_system.yaml --output report.json --format json
    python -m threat_model_agent.cli --input examples/sample_system.yaml --offline-demo
"""
import argparse
import json
import sys
from pathlib import Path

from .attack_mapper import AttackMapper
from .loader import load_system_model
from .report_generator import generate_markdown_report
from .stride_engine import ThreatModelingEngine


def main() -> int:
    parser = argparse.ArgumentParser(description="STRIDE threat modeling agent powered by Claude")
    parser.add_argument("--input", "-i", required=True, help="Path to system model YAML/JSON file")
    parser.add_argument("--output", "-o", default=None, help="Path to write the report to (default: stdout)")
    parser.add_argument(
        "--format", "-f", choices=["md", "json"], default="md", help="Output format (default: md)"
    )
    parser.add_argument(
        "--model", default="claude-sonnet-5", help="Claude model to use (default: claude-sonnet-5)"
    )
    parser.add_argument(
        "--offline-demo",
        action="store_true",
        help="Skip the API call and use the bundled example analysis (no API key needed, for demos)",
    )
    args = parser.parse_args()

    try:
        system = load_system_model(args.input)
    except Exception as exc:
        print(f"Error loading system model: {exc}", file=sys.stderr)
        return 1

    attack_mapper = AttackMapper()

    if args.offline_demo:
        demo_path = Path(__file__).resolve().parent.parent / "examples" / "sample_output.json"
        with open(demo_path, "r", encoding="utf-8") as f:
            analysis = json.load(f)
    else:
        try:
            engine = ThreatModelingEngine(model=args.model, attack_mapper=attack_mapper)
            analysis = engine.analyze(system)
        except Exception as exc:
            print(f"Error during analysis: {exc}", file=sys.stderr)
            return 1

    if args.format == "json":
        output_text = json.dumps(analysis, indent=2, ensure_ascii=False)
    else:
        output_text = generate_markdown_report(system, analysis, attack_mapper)

    if args.output:
        Path(args.output).write_text(output_text, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(output_text)

    return 0


if __name__ == "__main__":
    sys.exit(main())
