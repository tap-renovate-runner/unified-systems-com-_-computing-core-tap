"""The typed batch `parse_cyclonedx` returns: node rows, edge rows and a report of what was skipped.

Pure data. A row names itself by a batch-local ``ref``, never by an entity id: the grid assigns ids
and finds a row again by its natural key (``tap_grid/natural_key.py``), so the GRIFT importer
resolves every ref (``req-grid-import-grift-identity-3``). The one entity the batch does not create
is the host the document describes, which the caller already has an id for.

Spec: specs/spec-computing-core-v0.md (req-computing-core-sbom-parse).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

#: The dimension every type this plugin models carries (its models' ``DEFAULT_DIMENSIONS``).
RUNTIME_DIMENSIONS: Mapping[str, str] = {"tap.computing": "runtime"}


@dataclass(frozen=True)
class NodeRow:
    """One node to write: a type, a batch-local ref, an envelope name and the node's properties.

    The GRIFT envelope's ``name`` is a projection of the model's ``name`` field and the importer
    refuses a mismatch, so ``name`` equals ``properties["name"]`` wherever the type has one.
    """

    ref: str
    entity_type: str
    name: str
    properties: Mapping[str, Any]

    def as_grift(self) -> dict[str, Any]:
        """The GRIFT node envelope (``entity`` + ``node``) with ``ref`` in place of ``entity_id``."""
        return {
            "entity": {
                "ref": self.ref,
                "entity_type": self.entity_type,
                "name": self.name,
                "dimensions": dict(RUNTIME_DIMENSIONS),
            },
            "node": dict(self.properties),
        }


@dataclass(frozen=True)
class EdgeRow:
    """One edge to write. Each end is a batch-local ref, or the entity id of the caller's host."""

    ref: str
    edge_type: str
    from_ref: str | None = None
    from_entity_id: str | None = None
    to_ref: str | None = None
    to_entity_id: str | None = None

    def as_grift(self) -> dict[str, Any]:
        """The GRIFT edge envelope: ``ref`` on the entity, one of ``*_ref`` / ``*_entity_id`` per end."""
        payload: dict[str, Any] = {"edge_type": self.edge_type, "properties": {}}
        for key in ("from_ref", "from_entity_id", "to_ref", "to_entity_id"):
            value = getattr(self, key)
            if value is not None:
                payload[key] = value
        return {
            "entity": {"ref": self.ref, "entity_type": "edge", "dimensions": dict(RUNTIME_DIMENSIONS)},
            "edge": payload,
        }


@dataclass(frozen=True)
class SbomReport:
    """What the parser counted, skipped and chose, so nothing is dropped silently (sbom-parse-8)."""

    component_count: int
    """Components the document lists, nested ones included."""
    skipped_components: Mapping[str, int] = field(default_factory=dict)
    """Reason -> count for components that became no node (no name, no version, unsupported purl type, ...)."""
    skipped_dependencies: Mapping[str, int] = field(default_factory=dict)
    """Reason -> count for ``dependsOn`` entries that became no edge (non-package end, unlisted, self)."""
    duplicate_components_collapsed: int = 0
    """Components listed again under an already-seen (ecosystem, name, version): one node each."""
    duplicate_dependencies_collapsed: int = 0
    """``dependsOn`` entries that named a package pair an earlier entry already named."""
    purl_conflicts: tuple[str, ...] = ()
    """For a duplicated key with different purls: the key, the purl kept and the ones dropped."""
    notes: tuple[str, ...] = ()
    """Other values the parser left out, each with its reason (an architecture that is not one token, ...)."""


@dataclass(frozen=True)
class SbomBatch:
    """Everything one document gives the grid: rows sorted so equal input is equal output."""

    nodes: tuple[NodeRow, ...]
    edges: tuple[EdgeRow, ...]
    report: SbomReport

    def nodes_of(self, entity_type: str) -> tuple[NodeRow, ...]:
        """The node rows of one entity type, for example ``computing_core__package``."""
        return tuple(n for n in self.nodes if n.entity_type == entity_type)

    def edges_of(self, edge_type: str) -> tuple[EdgeRow, ...]:
        """The edge rows of one edge type, for example ``REQUIRES_PACKAGE__computing_core``."""
        return tuple(e for e in self.edges if e.edge_type == edge_type)

    def as_grift_batch(self, batch_entity_id: str, *, name: str, source: str) -> dict[str, Any]:
        """One GRIFT batch container holding these rows, for ``grift_import``.

        ``batch_entity_id`` is the caller's id for the batch entity (a UUID); the batch itself is
        the one thing the importer does not resolve by ref.
        """
        return {
            "batch_entity": {"entity_id": batch_entity_id, "entity_type": "batch", "name": name, "dimensions": {}},
            "batch_node": {"name": name, "description": "", "source": source, "metadata": {}},
            "nodes": [n.as_grift() for n in self.nodes],
            "edges": [e.as_grift() for e in self.edges],
        }
