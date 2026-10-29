"""Host — a computing environment that runs an operating system and executes programs."""

import re
from typing import Any, ClassVar

from django.core.exceptions import ValidationError
from django.db import models

from tap_grid.models import BaseModel

#: The shape of ``stable_id`` for a realm that fixes one (``req-computing-core-host-4``). A realm
#: not listed here is not checked: the column stays open text, and the spec's "Realms in use" table
#: is the record of what each value means. ``oci-digest`` is a container image's manifest digest.
STABLE_ID_PATTERNS: dict[str, str] = {"oci-digest": r"sha256:[0-9a-f]{64}"}

#: Closed vocabulary for `host.kind` (computing-core#8). Physical-versus-virtual is a property of
#: one durable type, not a family of types: at collection time a collector often cannot tell a
#: hosted runner's VM from bare metal, and `unknown` is the honest answer when it cannot.
HOST_KINDS: tuple[str, ...] = (
    "workstation",
    "server",
    "virtual_machine",
    "container",
    "ephemeral_runner",
    "cloud_dev_environment",
    "unknown",
)


class Host(BaseModel):
    """A computing environment that runs an operating system and executes programs.

    One type for a laptop, a server, a VM, a container, a CI runner or a cloud dev environment;
    which of those it is lives in ``kind``. It carries no hardware facts (CPU, chassis, serial):
    it is the OS-bearing environment the spec's scope already names, not the hardware below it.

    Identity is ``(realm, stable_id)``: the authority that issued a stable identifier for this
    host, and that identifier. An EC2 instance is ``("aws-ec2", "i-0abc…")``, a GitHub-hosted
    runner pool ``("github-runner", "<label set>")``, a Linux machine ``("machine-id", "<the
    contents of /etc/machine-id>")``, an operator's assertion ``("assert", "<slug>")``. Not the
    hostname, which an operator changes and which two machines can share. Two realms that see
    one machine mint two hosts; joining them is a separate assertion, never an inference.

    Local accounts and groups live on a host and retire with it: ``DEFINES_OS_USER`` and
    ``DEFINES_OS_GROUP`` are containment.

    Spec: specs/spec-computing-core-v0.md (req-computing-core-host).
    """

    ENTITY_TYPE: ClassVar[str] = "computing_core__host"
    ENTITY_NAME: ClassVar[str] = "Host"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "A computing environment that runs an operating system and executes programs: a "
        "workstation, server, virtual machine, container or CI runner. Whether it is physical "
        "or virtual is its kind, not its type."
    )
    ENTITY_ICON: ClassVar[str] = "host"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {"tap.computing": "host"}
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("realm", "stable_id")
    DEFAULT_DISPLAY: ClassVar[dict[str, Any]] = {
        "tap_viz": {
            "shape": "round-rectangle",
            "colors": {"fill": "#4A6F8A", "border": "#22394A", "label": "#FFFFFF"},
        }
    }

    # Accounts and groups defined in this host's own account database exist only as part of it.
    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "computing_core__os_user"}], "edges": [{"type": "DEFINES_OS_USER__computing_core"}]},
        {"nodes": [{"type": "computing_core__os_group"}], "edges": [{"type": "DEFINES_OS_GROUP__computing_core"}]},
        # What is installed on the host and which OS it runs are references: a package or an OS
        # outlives any one host and is shared by many, so neither is in CONTAINMENT_EDGES.
        {"nodes": [{"type": "computing_core__package"}], "edges": [{"type": "INSTALLS_PACKAGE__computing_core"}]},
        {
            "nodes": [{"type": "computing_core__operating_system"}],
            "edges": [{"type": "RUNS_OPERATING_SYSTEM__computing_core"}],
        },
        # A host may send an application flow. The flow edges declare no endpoints, and core registers
        # an edge that declares neither end as no constraint at all, so a type that declares its
        # edges (this one) must name them itself or the grid refuses them.
        {
            "nodes": [{"type": "computing_core__application_flow"}],
            "edges": [{"type": "APPLICATION_FLOW_SOURCE__computing_core"}],
        },
    ]
    # An SBOM document inventories the host; the document is a reference, never containment.
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {
            "nodes": [{"type": "computing_core__sbom_document"}],
            "edges": [{"type": "DESCRIBES_HOST__computing_core"}],
        },
        # ... and may receive one, for the same reason.
        {
            "nodes": [{"type": "computing_core__application_flow"}],
            "edges": [{"type": "APPLICATION_FLOW_DESTINATION__computing_core"}],
        },
    ]
    CONTAINMENT_EDGES: ClassVar[tuple[str, ...]] = (
        "DEFINES_OS_USER__computing_core",
        "DEFINES_OS_GROUP__computing_core",
    )

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "realm": {"type": "string", "minLength": 1},
        "stable_id": {"type": "string", "minLength": 1},
        "name": {"type": "string"},
        "kind": {"type": ["string", "null"], "enum": [*HOST_KINDS, None]},
        "os": {"type": "string"},
        "ephemeral": {"type": ["boolean", "null"]},
    }
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        "realm": {"validation": "jsonschema", "schema": {"type": "string", "minLength": 1}},
        "stable_id": {"validation": "jsonschema", "schema": {"type": "string", "minLength": 1}},
        "name": {"validation": "jsonschema", "schema": {"type": "string"}},
        "kind": {"validation": "jsonschema", "schema": {"type": ["string", "null"], "enum": [*HOST_KINDS, None]}},
        "os": {"validation": "jsonschema", "schema": {"type": "string"}},
        "ephemeral": {"validation": "jsonschema", "schema": {"type": ["boolean", "null"]}},
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["realm", "stable_id"]

    realm = models.CharField(
        max_length=64,
        blank=True,
        default="",
        help_text="The authority that issued stable_id (aws-ec2, github-runner, machine-id, assert, ...).",
    )
    stable_id = models.CharField(
        max_length=255,
        blank=True,
        default="",
        help_text="The host's identifier within realm. Never the hostname.",
    )
    name = models.CharField(max_length=255, blank=True, default="", help_text="Display name; usually the hostname.")
    kind = models.CharField(  # noqa: DJ001  (req-computing-core-host-2)
        max_length=32,
        blank=True,
        null=True,
        default=None,
        help_text="One of HOST_KINDS. Null = not observed; 'unknown' = looked and could not tell.",
    )
    os = models.CharField(
        max_length=255,
        blank=True,
        default="",
        help_text="The operating system as reported (linux, macOS 15.6, Windows Server 2022).",
    )
    ephemeral = models.BooleanField(
        null=True,
        blank=True,
        default=None,
        help_text="True when nothing survives between uses (a hosted CI runner). Null = not observed.",
    )

    class Meta(BaseModel.Meta):
        db_table = "computing_core__host"

    def validate(self) -> None:
        """``stable_id`` has the shape its realm fixes, when the realm fixes one (req-computing-core-host-4)."""
        pattern = STABLE_ID_PATTERNS.get(self.realm)
        if pattern is not None and not re.fullmatch(pattern, self.stable_id):
            raise ValidationError({"stable_id": [f"stable_id for realm {self.realm!r} must match {pattern}."]})

    def get_name(self) -> str:
        return self.name or self.stable_id

    def __str__(self) -> str:
        return self.get_name()
