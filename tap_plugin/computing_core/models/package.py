"""Package — one release of a distribution or language-ecosystem package, as an inventory lists it."""

from typing import Any, ClassVar

from django.core.exceptions import ValidationError
from django.db import models

from tap_grid.models import BaseModel

#: A package-URL type (https://github.com/package-url/purl-spec): ``apk``, ``deb``, ``rpm``,
#: ``pypi``, ``npm``, ``golang``, ``generic``. Open vocabulary on purpose: the purl spec adds
#: types, and a closed list here would refuse a real package manager on the day it appears.
PURL_TYPE_PATTERN = r"^[a-z][a-z0-9.+-]*$"

#: One architecture token as a package manager or a purl ``arch=`` qualifier writes it
#: (``x86_64``, ``aarch64``, ``noarch``, ``amd64``, ``armhf``). It has no comma and no space, so a
#: joined value such as ``aarch64, x86_64`` is refused (req-computing-core-package-8).
ARCHITECTURE_PATTERN = r"^[A-Za-z0-9_.-]*$"

#: The ``cpe_candidates`` list as a JSON Schema, declared once and used by both schema dicts below.
CPE_CANDIDATES_SCHEMA: dict[str, Any] = {
    "type": "array",
    "description": "The other CPE 2.3 names a document lists for this component; unique, none repeating cpe.",
    "uniqueItems": True,
    "items": {
        "type": "string",
        "description": "One CPE 2.3 formatted string, starting cpe:2.3:.",
        "pattern": r"^cpe:2\.3:",
    },
}


class Package(BaseModel):
    """A package a package manager installed: an apk, deb or rpm, a Python or npm distribution.

    One node per ``(ecosystem, name, version)``, the unit an SBOM lists and a scanner matches
    advisories against. Not a library: a ``library`` is code an application imports or links
    that was built outside a package manager; a package is the unit the manager installs and may
    bundle many things (``SHIPS_LIBRARY``). A scanner finding attaches to a package with the
    existing ``CARRIES_COMPLIANCE_FINDING`` edge, whose source side is open.

    The names follow CycloneDX components (``name``, ``version``, ``purl``, ``cpe``, ``licenses``)
    so an SBOM row maps in without translation; ``ecosystem`` is the purl type.

    Spec: specs/spec-computing-core-v0.md (req-computing-core-package).
    """

    ENTITY_TYPE: ClassVar[str] = "computing_core__package"
    ENTITY_NAME: ClassVar[str] = "Package"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "A package a package manager installed (an apk, deb or rpm; a Python or npm distribution), "
        "one node per ecosystem, name and version. The unit an SBOM lists and a scanner matches "
        "advisories against. Hosts install it; a library it ships, or crypto it carries, hang off it."
    )
    ENTITY_ICON: ClassVar[str] = "package"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {"tap.computing": "runtime"}
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("ecosystem", "name", "version")
    DEFAULT_DISPLAY: ClassVar[dict[str, Any]] = {
        "tap_viz": {
            "shape": "rectangle",
            "colors": {"fill": "#8C6FB5", "border": "#5A4082", "label": "#FFFFFF"},
        }
    }

    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "computing_core__library"}], "edges": [{"type": "SHIPS_LIBRARY__computing_core"}]},
        {"nodes": [{"type": "computing_core__package"}], "edges": [{"type": "REQUIRES_PACKAGE__computing_core"}]},
        {
            "nodes": [{"type": "computing_core__crypto_provider"}],
            "edges": [{"type": "CARRIES_CRYPTO_PROVIDER__computing_core"}],
        },
        {
            "nodes": [{"type": "computing_core__source_package"}],
            "edges": [{"type": "DERIVES_FROM_SOURCE_PACKAGE__computing_core"}],
        },
    ]
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "computing_core__host"}], "edges": [{"type": "INSTALLS_PACKAGE__computing_core"}]},
        {"nodes": [{"type": "computing_core__package"}], "edges": [{"type": "REQUIRES_PACKAGE__computing_core"}]},
    ]

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "ecosystem": {"type": "string", "pattern": PURL_TYPE_PATTERN},
        "name": {"type": "string", "minLength": 1},
        "version": {"type": "string", "minLength": 1},
        "architecture": {"type": "string", "pattern": ARCHITECTURE_PATTERN},
        "purl": {"type": "string"},
        "cpe": {"type": "string"},
        "cpe_candidates": CPE_CANDIDATES_SCHEMA,
        "license": {"type": "string"},
        "source_document": {"type": "string"},
    }
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        "ecosystem": {"validation": "jsonschema", "schema": {"type": "string", "pattern": PURL_TYPE_PATTERN}},
        "name": {"validation": "jsonschema", "schema": {"type": "string", "minLength": 1}},
        "version": {"validation": "jsonschema", "schema": {"type": "string", "minLength": 1}},
        "architecture": {"validation": "jsonschema", "schema": {"type": "string", "pattern": ARCHITECTURE_PATTERN}},
        "purl": {"validation": "jsonschema", "schema": {"type": "string"}},
        "cpe": {"validation": "jsonschema", "schema": {"type": "string"}},
        "cpe_candidates": {"validation": "jsonschema", "schema": CPE_CANDIDATES_SCHEMA},
        "license": {"validation": "jsonschema", "schema": {"type": "string"}},
        "source_document": {"validation": "jsonschema", "schema": {"type": "string"}},
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["ecosystem", "name", "version"]

    ecosystem = models.CharField(
        max_length=32,
        blank=True,
        default="",
        db_index=True,
        help_text="The package-URL type of the manager that installs it: apk, deb, rpm, pypi, npm, generic, ...",
    )
    name = models.CharField(max_length=255, blank=True, default="", db_index=True, help_text="Package name.")
    version = models.CharField(
        max_length=128, blank=True, default="", help_text="Version exactly as the package manager reports it."
    )
    architecture = models.CharField(
        max_length=32,
        blank=True,
        default="",
        help_text="CPU architecture as last reported (x86_64, aarch64, noarch). Empty where the ecosystem has none. Not part of identity.",
    )
    purl = models.CharField(
        max_length=1024, blank=True, default="", help_text="Package URL (pkg:apk/wolfi/glibc@2.44-r6?arch=x86_64)."
    )
    cpe = models.CharField(
        max_length=512, blank=True, default="", help_text="CPE 2.3 name, where the document supplies one."
    )
    cpe_candidates = models.JSONField(
        default=list,
        blank=True,
        help_text=(
            "The other CPE 2.3 names the document lists for this component (Syft's repeated syft:cpe23 "
            "properties), each starting cpe:2.3:, never repeating cpe. Empty where it lists none. Not identity."
        ),
    )
    license = models.CharField(max_length=512, blank=True, default="", help_text="SPDX licence expression.")
    source_document = models.CharField(
        max_length=64,
        blank=True,
        default="",
        help_text="The document the most recent observation of this package came from (sbom, uv.lock, supplemental).",
    )

    class Meta(BaseModel.Meta):
        db_table = "computing_core__package"

    def validate(self) -> None:
        """``cpe_candidates`` never repeats ``cpe`` (req-computing-core-package-7)."""
        if self.cpe and isinstance(self.cpe_candidates, list) and self.cpe in self.cpe_candidates:
            raise ValidationError({"cpe_candidates": ["cpe_candidates must not repeat cpe."]})

    def get_name(self) -> str:
        return f"{self.name} {self.version}".strip()

    def __str__(self) -> str:
        return self.get_name()
