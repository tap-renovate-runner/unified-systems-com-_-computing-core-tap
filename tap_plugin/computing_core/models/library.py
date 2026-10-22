"""Library — code an application imports or links, built or vendored outside a package manager."""

from typing import Any, ClassVar

from django.db import models
from tap_plugin.computing_core.models.package import PURL_TYPE_PATTERN

from tap_grid.models import BaseModel

#: How a library came to be in the artifact without a package manager installing it. The values
#: are the ``source_kind`` vocabulary of tap's ``docker/sbom-supplemental.json`` (req-cicd-sbom-3)
#: plus ``source-built`` for a registry package compiled from its sdist (req-cicd-sbom-12-6).
LIBRARY_SOURCE_KINDS: tuple[str, ...] = ("self-built", "source-built", "copied-image")


class Library(BaseModel):
    """A programmatic library an application imports or links, built or vendored by us.

    The things a package manager does not describe: the OpenSSL FIPS provider compiled from a
    pinned tarball, the ``cryptography`` wheel compiled from source against the system OpenSSL.
    They are the components an SBOM can only know about because someone declared them, and the
    ones a vulnerability has to be attributed to by hand. A library a package manager installs is
    a ``package``; ``SHIPS_LIBRARY`` connects a package to a library it bundles.

    Whether a library carries cryptography is not a column: it is the presence of a
    ``CARRIES_CRYPTO_PROVIDER`` edge to a ``crypto_provider``, which also says which provider and
    how it was dispositioned. A second flag beside the edge would be two writable copies of one fact.

    Spec: specs/spec-computing-core-v0.md (req-computing-core-library).
    """

    ENTITY_TYPE: ClassVar[str] = "computing_core__library"
    ENTITY_NAME: ClassVar[str] = "Library"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "A programmatic library an application imports or links that was built or vendored outside "
        "a package manager: a provider compiled from a pinned tarball, a Python distribution built "
        "from source. Programs load it; it can carry cryptography."
    )
    ENTITY_ICON: ClassVar[str] = "library"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {"tap.computing": "runtime"}
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("ecosystem", "name", "version")
    DEFAULT_DISPLAY: ClassVar[dict[str, Any]] = {
        "tap_viz": {
            "shape": "rectangle",
            "colors": {"fill": "#6F8FB5", "border": "#3F5F82", "label": "#FFFFFF"},
        }
    }

    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {
            "nodes": [{"type": "computing_core__crypto_provider"}],
            "edges": [{"type": "CARRIES_CRYPTO_PROVIDER__computing_core"}],
        },
        {"nodes": [{"type": "computing_core__module"}], "edges": [{"type": "CONTAINS_MODULE__computing_core"}]},
    ]
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "computing_core__program"}], "edges": [{"type": "LOADS_LIBRARY__computing_core"}]},
        {"nodes": [{"type": "computing_core__package"}], "edges": [{"type": "SHIPS_LIBRARY__computing_core"}]},
    ]

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "ecosystem": {"type": "string", "pattern": PURL_TYPE_PATTERN},
        "name": {"type": "string", "minLength": 1},
        "version": {"type": "string", "minLength": 1},
        "language": {"type": "string"},
        "purl": {"type": "string"},
        "cpe": {"type": "string"},
        "license": {"type": "string"},
        "source_kind": {"type": ["string", "null"], "enum": [*LIBRARY_SOURCE_KINDS, None]},
        "source_url": {"type": "string"},
        "path": {"type": "string"},
    }
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        "ecosystem": {"validation": "jsonschema", "schema": {"type": "string", "pattern": PURL_TYPE_PATTERN}},
        "name": {"validation": "jsonschema", "schema": {"type": "string", "minLength": 1}},
        "version": {"validation": "jsonschema", "schema": {"type": "string", "minLength": 1}},
        "language": {"validation": "jsonschema", "schema": {"type": "string"}},
        "purl": {"validation": "jsonschema", "schema": {"type": "string"}},
        "cpe": {"validation": "jsonschema", "schema": {"type": "string"}},
        "license": {"validation": "jsonschema", "schema": {"type": "string"}},
        "source_kind": {
            "validation": "jsonschema",
            "schema": {"type": ["string", "null"], "enum": [*LIBRARY_SOURCE_KINDS, None]},
        },
        "source_url": {"validation": "jsonschema", "schema": {"type": "string"}},
        "path": {"validation": "jsonschema", "schema": {"type": "string"}},
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["ecosystem", "name", "version"]

    ecosystem = models.CharField(
        max_length=32,
        blank=True,
        default="",
        db_index=True,
        help_text="The package-URL type of its identity: pypi, npm, generic (a tarball with no registry), ...",
    )
    name = models.CharField(max_length=255, blank=True, default="", db_index=True, help_text="Library name.")
    version = models.CharField(max_length=128, blank=True, default="", help_text="Version as built.")
    language = models.CharField(
        max_length=32, blank=True, default="", help_text="Implementation language (c, python, rust, go)."
    )
    purl = models.CharField(max_length=1024, blank=True, default="", help_text="Package URL.")
    cpe = models.CharField(
        max_length=512,
        blank=True,
        default="",
        help_text="CPE 2.3 name. For a pkg:generic library it is what lets an advisory feed match at all.",
    )
    license = models.CharField(max_length=512, blank=True, default="", help_text="SPDX licence expression.")
    source_kind = models.CharField(  # noqa: DJ001  (req-computing-core-library-3)
        max_length=16,
        blank=True,
        null=True,
        default=None,
        help_text="One of LIBRARY_SOURCE_KINDS: how it entered the artifact. Null = not observed.",
    )
    source_url = models.CharField(
        max_length=1024, blank=True, default="", help_text="Where the source it was built from was fetched."
    )
    path = models.CharField(
        max_length=1024,
        blank=True,
        default="",
        help_text="Where it sits in the artifact (/usr/lib/ossl-modules/fips.so).",
    )

    class Meta(BaseModel.Meta):
        db_table = "computing_core__library"

    def get_name(self) -> str:
        return f"{self.name} {self.version}".strip()

    def __str__(self) -> str:
        return self.get_name()
