"""
Data models describing a system for STRIDE threat modeling.

These map loosely onto standard Data Flow Diagram (DFD) primitives:
- Component  -> process / datastore / external entity / actor
- DataFlow   -> arrow between two components
- TrustBoundary -> dashed line grouping components by trust level
"""
from dataclasses import dataclass, field
from typing import List, Optional


VALID_COMPONENT_TYPES = {"process", "datastore", "external_entity", "actor"}
VALID_TRUST_ZONES = {"internet", "dmz", "internal", "restricted"}
VALID_DATA_CLASSIFICATIONS = {"public", "internal", "confidential", "restricted"}


@dataclass
class Component:
    id: str
    name: str
    type: str = "process"
    description: str = ""
    trust_zone: str = "internal"
    technologies: List[str] = field(default_factory=list)

    def validate(self) -> List[str]:
        errors = []
        if self.type not in VALID_COMPONENT_TYPES:
            errors.append(
                f"Component '{self.id}': invalid type '{self.type}', "
                f"expected one of {sorted(VALID_COMPONENT_TYPES)}"
            )
        if self.trust_zone not in VALID_TRUST_ZONES:
            errors.append(
                f"Component '{self.id}': invalid trust_zone '{self.trust_zone}', "
                f"expected one of {sorted(VALID_TRUST_ZONES)}"
            )
        return errors


@dataclass
class DataFlow:
    id: str
    source: str
    destination: str
    description: str = ""
    data_classification: str = "internal"
    protocol: str = ""
    crosses_trust_boundary: bool = False

    def validate(self, component_ids: set) -> List[str]:
        errors = []
        if self.source not in component_ids:
            errors.append(f"DataFlow '{self.id}': unknown source component '{self.source}'")
        if self.destination not in component_ids:
            errors.append(f"DataFlow '{self.id}': unknown destination component '{self.destination}'")
        if self.data_classification not in VALID_DATA_CLASSIFICATIONS:
            errors.append(
                f"DataFlow '{self.id}': invalid data_classification '{self.data_classification}', "
                f"expected one of {sorted(VALID_DATA_CLASSIFICATIONS)}"
            )
        return errors


@dataclass
class TrustBoundary:
    id: str
    name: str
    description: str = ""


@dataclass
class SystemModel:
    name: str
    description: str
    components: List[Component]
    data_flows: List[DataFlow]
    trust_boundaries: List[TrustBoundary] = field(default_factory=list)

    def validate(self) -> List[str]:
        errors = []
        component_ids = {c.id for c in self.components}
        if len(component_ids) != len(self.components):
            errors.append("Duplicate component IDs detected")
        for c in self.components:
            errors.extend(c.validate())
        for f in self.data_flows:
            errors.extend(f.validate(component_ids))
        return errors

    def component_by_id(self, component_id: str) -> Optional[Component]:
        for c in self.components:
            if c.id == component_id:
                return c
        return None
