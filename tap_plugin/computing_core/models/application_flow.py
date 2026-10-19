"""Application flow — the conceptual aggregate of traffic between a source and a destination."""

from typing import Any, ClassVar

from django.db import models

from tap_grid.models import BaseModel
from tap_grid.natural_key import KEYLESS, Keyless


class ApplicationFlow(BaseModel):
    """Traffic between a sender and a receiver, as one node the two ends hang from.

    Not a connection and not a session: ``tcp_connection`` is a transport session a source system
    observes, and an application flow is the aggregate a person names above it. It carries a
    ``name`` and a ``description`` and nothing else; the sender and receiver are the
    ``APPLICATION_FLOW_SOURCE`` and ``APPLICATION_FLOW_DESTINATION`` edges, which take any node type
    at either end.
    """

    ENTITY_TYPE: ClassVar[str] = "computing_core__application_flow"
    ENTITY_NAME: ClassVar[str] = "Application Flow"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "A conceptual aggregate of traffic between a source and a destination, joined to them by "
        "APPLICATION_FLOW_SOURCE and APPLICATION_FLOW_DESTINATION edges."
    )
    ENTITY_ICON: ClassVar[str] = "application-flow"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {"tap.computing": "network"}
    NATURAL_KEY: ClassVar[Keyless] = KEYLESS
    NATURAL_KEY_REASON: ClassVar[str] = (
        "An application flow is a conceptual aggregate of traffic between a source and a destination; "
        "no source system observes it, so it has no stable identifier to key on yet. "
        "A natural key will be declared when one is found."
    )
    DEFAULT_DISPLAY: ClassVar[dict[str, Any]] = {
        "tap_viz": {
            "shape": "rectangle",
            "colors": {"fill": "#B28E5E", "border": "#835C2B", "label": "#FFFFFF"},
        }
    }

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "name": {"type": "string"},
        "description": {"type": "string"},
    }

    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        "name": {"validation": "jsonschema", "schema": {"type": "string"}},
        "description": {"validation": "jsonschema", "schema": {"type": "string"}},
    }
    CREATE_REQUIRED: ClassVar[list[str]] = []

    name = models.CharField(max_length=255, blank=True, default="")
    description = models.TextField(blank=True, default="")

    class Meta(BaseModel.Meta):
        db_table = "computing_core__application_flow"

    def get_name(self) -> str:
        return self.name or "application flow"

    def __str__(self) -> str:
        return self.get_name()
