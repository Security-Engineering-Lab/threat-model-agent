"""
Loads a system description from YAML or JSON into a SystemModel.
"""
import json
from pathlib import Path
from typing import Union

import yaml

from .models import Component, DataFlow, SystemModel, TrustBoundary


def load_system_model(path: Union[str, Path]) -> SystemModel:
    path = Path(path)
    text = path.read_text(encoding="utf-8")

    if path.suffix.lower() in (".yaml", ".yml"):
        raw = yaml.safe_load(text)
    elif path.suffix.lower() == ".json":
        raw = json.loads(text)
    else:
        raise ValueError(f"Unsupported file extension: {path.suffix} (use .yaml or .json)")

    components = [Component(**c) for c in raw.get("components", [])]
    data_flows = [DataFlow(**f) for f in raw.get("data_flows", [])]
    trust_boundaries = [TrustBoundary(**b) for b in raw.get("trust_boundaries", [])]

    model = SystemModel(
        name=raw.get("name", "Unnamed System"),
        description=raw.get("description", ""),
        components=components,
        data_flows=data_flows,
        trust_boundaries=trust_boundaries,
    )

    errors = model.validate()
    if errors:
        raise ValueError(
            "System model validation failed:\n" + "\n".join(f"  - {e}" for e in errors)
        )

    return model
