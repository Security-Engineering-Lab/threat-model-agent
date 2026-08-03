#!/usr/bin/env bash
# Runs the full pipeline: clone django-azure-app -> scan -> review YAML -> STRIDE analysis.
#
# Run from the root of the threat-model-agent repo in your Codespace:
#   chmod +x run_pipeline.sh
#   ./run_pipeline.sh
#
# Requires ANTHROPIC_API_KEY set (e.g. as a Codespace secret) for the final
# analysis step. The scan step alone does not call the API.
#
# Usage:
#   ./run_pipeline.sh                 # clone + scan + analyze
#   ./run_pipeline.sh --scan-only     # clone + scan only, skip the API call
#   ./run_pipeline.sh --skip-clone    # reuse existing ../django-azure-app checkout

set -euo pipefail

SCAN_ONLY=false
SKIP_CLONE=false

for arg in "$@"; do
  case "$arg" in
    --scan-only) SCAN_ONLY=true ;;
    --skip-clone) SKIP_CLONE=true ;;
    *) echo "Unknown option: $arg" >&2; exit 1 ;;
  esac
done

if [ ! -f "threat_model_agent/cli.py" ]; then
  echo "ERROR: run this script from the threat-model-agent repo root." >&2
  exit 1
fi

TARGET_REPO_URL="https://github.com/Python-Development-Lab/django-azure-app.git"
TARGET_REPO_DIR="../django-azure-app"
SCANNED_YAML="examples/scanned_system.yaml"
REPORT_MD="report.md"

if [ "$SKIP_CLONE" = false ]; then
  if [ -d "$TARGET_REPO_DIR" ]; then
    echo "==> $TARGET_REPO_DIR already exists, pulling latest instead of cloning"
    git -C "$TARGET_REPO_DIR" pull --ff-only
  else
    echo "==> Cloning $TARGET_REPO_URL"
    git clone "$TARGET_REPO_URL" "$TARGET_REPO_DIR"
  fi
else
  echo "==> --skip-clone set, reusing $TARGET_REPO_DIR as-is"
  if [ ! -d "$TARGET_REPO_DIR" ]; then
    echo "ERROR: $TARGET_REPO_DIR does not exist. Remove --skip-clone or clone it manually." >&2
    exit 1
  fi
fi

echo ""
echo "==> Scanning $TARGET_REPO_DIR -> $SCANNED_YAML"
python -m threat_model_agent.scan_cli \
  --repo "$TARGET_REPO_DIR" \
  --output "$SCANNED_YAML"

echo ""
echo "==> Generated system model:"
echo "--------------------------------------------------------------"
cat "$SCANNED_YAML"
echo "--------------------------------------------------------------"
echo ""
echo "Review the model above before continuing. Look especially for:"
echo "  - '⚠' markers (missing diagnostic logging, broad role/permission grants)"
echo "  - components/flows you expected but don't see (module-based resources"
echo "    or for_each/count blocks may not be picked up by the regex scanner)"
echo ""

if [ "$SCAN_ONLY" = true ]; then
  echo "==> --scan-only set, stopping before the Claude API call."
  exit 0
fi

if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
  echo "ERROR: ANTHROPIC_API_KEY is not set. Set it (e.g. as a Codespace secret)" >&2
  echo "or re-run with --scan-only to stop here without calling the API." >&2
  exit 1
fi

read -r -p "Proceed with the STRIDE analysis via the Claude API? This uses your quota. [y/N] " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
  echo "Aborted before the API call."
  exit 0
fi

echo ""
echo "==> Running STRIDE analysis -> $REPORT_MD"
python -m threat_model_agent.cli \
  --input "$SCANNED_YAML" \
  --output "$REPORT_MD"

echo ""
echo "==> Report:"
echo "--------------------------------------------------------------"
cat "$REPORT_MD"
echo "--------------------------------------------------------------"
