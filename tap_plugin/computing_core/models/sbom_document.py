"""SBOM document — the record that one software bill of materials existed, never its body."""

from typing import Any, ClassVar

from django.core.exceptions import ValidationError
from django.db import models

from tap_grid.models import BaseModel

#: A SHA-256 digest as 64 lower-case hex characters (req-computing-core-sbom-document-1).
SHA256_HEX_PATTERN = r"^[0-9a-f]{64}$"

#: A document format name, lower-case and open (``cyclonedx`` now, ``spdx`` when it is read).
FORMAT_PATTERN = r"^[a-z][a-z0-9-]*$"

#: A CycloneDX ``serialNumber`` (``urn:uuid:…``), or empty where the document has none.
SERIAL_NUMBER_PATTERN = r"^(urn:uuid:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})?$"

#: An artifact digest ``<algorithm>:<hex>`` (an image digest ``sha256:…``), or empty.
SUBJECT_DIGEST_PATTERN = r"^([a-z0-9]+:[0-9a-f]+)?$"


class SbomDocument(BaseModel):
    """The record that one SBOM existed: which bytes, which revision of which lineage, who signed.

    Not the SBOM. The document body is not stored on the grid (storing and serving the file is
    tap#1035); ``content_digest`` is how a copy held elsewhere is checked against this record.
    Keyed by that digest alone, so the same bytes are the same node and a rescan that changes any
    byte is a new node. Documents sharing ``(subject_digest, serial_number)`` are one lineage and
    the highest ``revision`` is the current one; earlier revisions are kept.

    ``verified`` is three-state and records an outcome the caller decided: ``True`` verified,
    ``False`` verification ran and failed, ``None`` not checked. ``signer`` is non-empty only when
    ``verified`` is ``True``.

    A document draws no edge to the packages it lists. What a host installs is its
    ``INSTALLS_PACKAGE`` edges; ``DESCRIBES_HOST`` joins the document to the host it inventories.

    Spec: specs/spec-computing-core-v0.md (req-computing-core-sbom-document).
    """

    ENTITY_TYPE: ClassVar[str] = "computing_core__sbom_document"
    ENTITY_NAME: ClassVar[str] = "SBOM Document"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "The record that one software bill of materials existed: the SHA-256 of its exact bytes, its "
        "format and revision, what it described, what generated it and who signed it. It is not the "
        "document: no body and no component list is stored, so the digest is how a copy held "
        "elsewhere is checked against the grid."
    )
    ENTITY_ICON: ClassVar[str] = "sbom-document"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {"tap.computing": "runtime"}
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("content_digest",)
    DEFAULT_DISPLAY: ClassVar[dict[str, Any]] = {
        "tap_viz": {
            "shape": "rectangle",
            "colors": {"fill": "#7FA0BF", "border": "#4C6C8A", "label": "#FFFFFF"},
        }
    }

    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "computing_core__host"}], "edges": [{"type": "DESCRIBES_HOST__computing_core"}]},
    ]

    # Declared empty on purpose: nothing points at a document. An undeclared side is open to any
    # edge whose other end allows it, so without this `sbom_document` would accept DESCRIBES_HOST
    # as a target (req-computing-core-sbom-document-4).
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = []

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "content_digest": {"type": "string", "pattern": SHA256_HEX_PATTERN},
        "format": {"type": "string", "pattern": FORMAT_PATTERN},
        "spec_version": {"type": "string"},
        "serial_number": {"type": "string", "pattern": SERIAL_NUMBER_PATTERN},
        "revision": {"type": "integer", "minimum": 1},
        "subject_digest": {"type": "string", "pattern": SUBJECT_DIGEST_PATTERN},
        "produced_at": {"type": ["string", "null"], "format": "date-time"},
        "generator": {"type": "string"},
        "component_count": {"type": "integer", "minimum": 0},
        "signer": {"type": "string"},
        "verified": {"type": ["boolean", "null"]},
    }
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        "content_digest": {"validation": "jsonschema", "schema": {"type": "string", "pattern": SHA256_HEX_PATTERN}},
        "format": {"validation": "jsonschema", "schema": {"type": "string", "pattern": FORMAT_PATTERN}},
        "spec_version": {"validation": "jsonschema", "schema": {"type": "string"}},
        "serial_number": {
            "validation": "jsonschema",
            "schema": {"type": "string", "pattern": SERIAL_NUMBER_PATTERN},
        },
        "revision": {"validation": "jsonschema", "schema": {"type": "integer", "minimum": 1}},
        "subject_digest": {
            "validation": "jsonschema",
            "schema": {"type": "string", "pattern": SUBJECT_DIGEST_PATTERN},
        },
        "generator": {"validation": "jsonschema", "schema": {"type": "string"}},
        "component_count": {"validation": "jsonschema", "schema": {"type": "integer", "minimum": 0}},
        "signer": {"validation": "jsonschema", "schema": {"type": "string"}},
        "verified": {"validation": "jsonschema", "schema": {"type": ["boolean", "null"]}},
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["content_digest"]

    content_digest = models.CharField(
        max_length=64,
        blank=True,
        default="",
        db_index=True,
        help_text="SHA-256 of the document's exact bytes, lower-case hex. Identity and the idempotency key.",
    )
    format = models.CharField(
        max_length=32,
        blank=True,
        default="cyclonedx",
        help_text="The document format: cyclonedx (spdx is not read yet).",
    )
    spec_version = models.CharField(
        max_length=16,
        blank=True,
        default="",
        help_text="The format's version as the document states it (CycloneDX specVersion: 1.7).",
    )
    serial_number = models.CharField(
        max_length=64,
        blank=True,
        default="",
        help_text="The document's serialNumber (urn:uuid:...). With subject_digest, names the lineage.",
    )
    revision = models.PositiveIntegerField(
        default=1, help_text="The document's own version counter, from 1. A rescan of one image is the next revision."
    )
    subject_digest = models.CharField(
        max_length=160,
        blank=True,
        default="",
        help_text="The digest of the artifact described (an image digest sha256:...). Empty where the document names none.",
    )
    produced_at = models.DateTimeField(
        null=True, blank=True, default=None, help_text="The document's metadata.timestamp. Null = it states none."
    )
    generator = models.CharField(
        max_length=255,
        blank=True,
        default="",
        help_text="The first tool that produced it, as name@version (syft@1.51.0).",
    )
    component_count = models.PositiveIntegerField(default=0, help_text="How many components the document lists.")
    signer = models.CharField(
        max_length=512,
        blank=True,
        default="",
        help_text="The identity of the verified signer. Non-empty only when verified is true.",
    )
    verified = models.BooleanField(
        null=True,
        blank=True,
        default=None,
        help_text="True verified, False verification ran and failed, Null not checked. The caller decides; this records it.",
    )

    class Meta(BaseModel.Meta):
        db_table = "computing_core__sbom_document"

    def validate(self) -> None:
        """``signer`` is non-empty only when ``verified`` is true (req-computing-core-sbom-document-3)."""
        if self.signer and self.verified is not True:
            raise ValidationError({"signer": ["signer may be set only when verified is true."]})

    def get_name(self) -> str:
        return f"sbom {self.content_digest[:12]} r{self.revision}".strip()

    def __str__(self) -> str:
        return self.get_name()
