"""Operating System — the OS an environment runs, identified by version and build."""

from typing import Any, ClassVar

from django.db import models

from tap_grid.models import BaseModel


class OperatingSystem(BaseModel):
    """An operating system as a distro publishes it: Wolfi, Ubuntu 24.04, Windows Server 2022.

    The operating-system row of the model catalog (``req-computing-core-models``), built. A
    ``host`` runs one (``RUNS_OPERATING_SYSTEM``); ``host.os`` stays the free-text report of the
    same fact and is not migrated (``req-computing-core-host``: it "can become its own node later
    without migrating this field").

    Identity is ``(os_id, version_id, build_id)``, all three taken as reported. ``os_id`` and
    ``version_id`` are ``/etc/os-release`` ``ID`` and ``VERSION_ID``. They are not enough for a
    rolling distribution: Wolfi reports ``ID=wolfi`` and a fixed placeholder ``VERSION_ID`` on
    every build, so those two fields alone would merge every Wolfi image ever built into one
    node. ``build_id`` is the third part: ``BUILD_ID`` where the distro sets one, and for a
    rolling distro the collector supplies what really pins the build (for a container, the
    digest of the pinned base image). Empty string means the OS reports none and is not rolling.

    Spec: specs/spec-computing-core-v0.md (req-computing-core-operating-system).
    """

    ENTITY_TYPE: ClassVar[str] = "computing_core__operating_system"
    ENTITY_NAME: ClassVar[str] = "Operating System"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "An operating system as a distro publishes it, identified by its os-release ID, VERSION_ID "
        "and a build identifier. For a rolling distribution such as Wolfi, whose VERSION_ID is a "
        "fixed placeholder, the build identifier (the pinned base-image digest) is what tells two "
        "builds apart."
    )
    ENTITY_ICON: ClassVar[str] = "operating-system"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {"tap.computing": "runtime"}
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("os_id", "version_id", "build_id")
    DEFAULT_DISPLAY: ClassVar[dict[str, Any]] = {
        "tap_viz": {
            "shape": "round-rectangle",
            "colors": {"fill": "#4F8F8F", "border": "#2A5F5F", "label": "#FFFFFF"},
        }
    }

    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "computing_core__host"}], "edges": [{"type": "RUNS_OPERATING_SYSTEM__computing_core"}]},
    ]

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "os_id": {"type": "string", "minLength": 1},
        "version_id": {"type": "string"},
        "build_id": {"type": "string"},
        "name": {"type": "string"},
        "vendor": {"type": "string"},
        "rolling": {"type": ["boolean", "null"]},
        "base_image": {"type": "string"},
        "end_of_life": {"type": ["string", "null"], "pattern": r"^\d{4}-\d{2}-\d{2}$"},
    }
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        "os_id": {"validation": "jsonschema", "schema": {"type": "string", "minLength": 1}},
        "version_id": {"validation": "jsonschema", "schema": {"type": "string"}},
        "build_id": {"validation": "jsonschema", "schema": {"type": "string"}},
        "name": {"validation": "jsonschema", "schema": {"type": "string"}},
        "vendor": {"validation": "jsonschema", "schema": {"type": "string"}},
        "rolling": {"validation": "jsonschema", "schema": {"type": ["boolean", "null"]}},
        "base_image": {"validation": "jsonschema", "schema": {"type": "string"}},
        "end_of_life": {
            "validation": "jsonschema",
            "schema": {"type": ["string", "null"], "pattern": r"^\d{4}-\d{2}-\d{2}$"},
        },
    }
    #: All three key parts must be PRESENT in a write (empty is a legitimate value for the last two).
    #: A collector that forgot ``build_id`` would otherwise mint a bogus node that looks like an
    #: OS reporting no build.
    CREATE_REQUIRED: ClassVar[list[str]] = ["os_id", "version_id", "build_id"]

    os_id = models.CharField(
        max_length=64, blank=True, default="", db_index=True, help_text="os-release ID: wolfi, ubuntu, debian, rhel."
    )
    version_id = models.CharField(
        max_length=64,
        blank=True,
        default="",
        help_text="os-release VERSION_ID exactly as reported, even when it is a placeholder (Wolfi: 20230201). Empty when the OS reports none.",
    )
    build_id = models.CharField(
        max_length=255,
        blank=True,
        default="",
        help_text="os-release BUILD_ID, or for a rolling distro what pins the build (a base-image digest). Empty = none and not rolling.",
    )
    name = models.CharField(max_length=255, blank=True, default="", help_text="Display name (os-release NAME).")
    vendor = models.CharField(max_length=255, blank=True, default="", help_text="Who publishes it (Chainguard).")
    rolling = models.BooleanField(
        null=True,
        blank=True,
        default=None,
        help_text="True for a rolling-release distro, whose version_id does not identify a build. Null = not observed.",
    )
    base_image = models.CharField(
        max_length=1024,
        blank=True,
        default="",
        help_text="The container image reference (with digest) this OS came from, when it came from one.",
    )
    end_of_life = models.DateField(
        null=True, blank=True, default=None, help_text="End-of-life date. Null = none published or not observed."
    )

    class Meta(BaseModel.Meta):
        db_table = "computing_core__operating_system"

    def get_name(self) -> str:
        return self.name or self.os_id

    def __str__(self) -> str:
        return self.get_name()
