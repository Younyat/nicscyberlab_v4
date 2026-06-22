from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class CausalNode:
    node_id: str
    node_type: str
    layer: str
    timestamp_utc: str | None
    label: str
    source_ref: str
    evidence_refs: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CausalEdge:
    edge_id: str
    expected_edge_id: str
    source: str
    target: str
    relation_type: str
    required_evidence: list[str]
    evidence_refs: list[str]
    missing_evidence: list[str]
    support_status: str
    confidence: str
    temporal_status: str
    semantic_status: str
    integrity_status: str
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CausalGraph:
    case_id: str
    scenario_id: str
    generated_at: str
    note: str
    nodes: list[CausalNode] = field(default_factory=list)
    edges: list[CausalEdge] = field(default_factory=list)

    def to_dict(self) -> dict:
        payload = asdict(self)
        payload["nodes"] = [node.to_dict() for node in self.nodes]
        payload["edges"] = [edge.to_dict() for edge in self.edges]
        return payload
