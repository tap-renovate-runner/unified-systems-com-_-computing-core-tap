"""Source package — the upstream source a binary package is built from."""

from typing import Any, ClassVar

from django.db import models
from tap_plugin.computing_core.models.package import PURL_TYPE_PATTERN

from tap_grid.models import BaseModel


class SourcePackage(BaseModel):
    """The source a package manager builds one or more binary packages from.

    An apk origin (``glibc-2.44`` builds ``glibc``, ``glibc-dev`` and ``ld-linux``), a deb
    ``Source:``, an rpm source RPM. A vulnerability scanner reports against the binary
    ``package``, but the thing to fix is the source, so counting or joining by source needs a
    node to count and join on. Each ``package`` draws ``DERIVES_FROM_SOURCE_PACKAGE`` to its
    source, including the package whose source is itself, so a join never needs a fallback.

    Keyed ``(ecosystem, name, version)``, the same shape as ``package``; ``ecosystem`` is the
    purl type of the manager that built it. The node holds the key and nothing else: ``purl``,
    ``cpe`` and ``license`` are facts about an installed binary and stay on the ``package``.

    Spec: specs/spec-computing-core-v0.md (req-computing-core-source-package).
    """

    ENTITY_TYPE: ClassVar[str] = "computing_core__source_package"
    ENTITY_NAME: ClassVar[str] = "Source Package"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "The upstream source a package manager builds binary packages from (an apk origin such as "
        "glibc-2.44 or python-3.14; a deb Source; an rpm source RPM), one node per ecosystem, name "
        "and version. A scanner reports against the binary package; the source is what gets fixed, "
        "so counts and joins by source hang off this node."
    )
    ENTITY_ICON: ClassVar[str] = "source-package"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {"tap.computing": "runtime"}
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("ecosystem", "name", "version")
    DEFAULT_DISPLAY: ClassVar[dict[str, Any]] = {
        "tap_viz": {
            "shape": "rectangle",
            "colors": {"fill": "#B58FCF", "border": "#7A5A96", "label": "#FFFFFF"},
        }
    }

    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {
            "nodes": [{"type": "computing_core__package"}],
            "edges": [{"type": "DERIVES_FROM_SOURCE_PACKAGE__computing_core"}],
        },
    ]

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "ecosystem": {"type": "string", "pattern": PURL_TYPE_PATTERN},
        "name": {"type": "string", "minLength": 1},
        "version": {"type": "string", "minLength": 1},
    }
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        "ecosystem": {"validation": "jsonschema", "schema": {"type": "string", "pattern": PURL_TYPE_PATTERN}},
        "name": {"validation": "jsonschema", "schema": {"type": "string", "minLength": 1}},
        "version": {"validation": "jsonschema", "schema": {"type": "string", "minLength": 1}},
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["ecosystem", "name", "version"]

    ecosystem = models.CharField(
        max_length=32,
        blank=True,
        default="",
        db_index=True,
        help_text="The package-URL type of the manager that builds it: apk, deb, rpm, ...",
    )
    name = models.CharField(
        max_length=255, blank=True, default="", db_index=True, help_text="Source package name (the apk origin)."
    )
    version = models.CharField(
        max_length=128, blank=True, default="", help_text="Version exactly as the package manager reports it."
    )

    class Meta(BaseModel.Meta):
        db_table = "computing_core__source_package"

    def get_name(self) -> str:
        return f"{self.name} {self.version}".strip()

    def __str__(self) -> str:
        return self.get_name()
