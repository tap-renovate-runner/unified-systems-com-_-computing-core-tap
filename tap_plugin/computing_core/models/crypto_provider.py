"""Crypto Provider — a cryptographic implementation found in an artifact, with its disposition."""

from typing import Any, ClassVar

from django.db import models

from tap_grid.models import BaseModel

#: The FIPS-boundary disposition of a provider. The values are tap's ``tap.crypto_providers.Boundary``
#: (req-fips-crypto-bom), spelled the same so a crypto-BOM finding maps in without translation.
CRYPTO_BOUNDARIES: tuple[str, ...] = (
    "validated",
    "fips-mode-unvalidated-build",
    "out-of-boundary",
    "unreached",
    "must-fix",
)

#: What kind of implementation it is, from tap's detection signatures (``Signature.kind``) plus the
#: module itself: the self-built OpenSSL FIPS provider is the validated module, not a user of it.
CRYPTO_PROVIDER_KINDS: tuple[str, ...] = ("fips-module", "system-openssl", "embedded-openssl", "non-openssl")


class CryptoProvider(BaseModel):
    """A cryptographic implementation present in an artifact, and what was decided about it.

    One node per ``(scope, artifact, provider)``: the finding tap's crypto-BOM gate produces for
    a native binary, an installed distribution or a plugin's source (``req-fips-crypto-bom``).
    ``provider`` names the implementation (``openssl-system``, ``openssl-fips-provider``,
    ``go-crypto``, ``rust-aws-lc-rs``, ``libsodium``); ``boundary`` is the reviewed decision about
    it. Code that carries it points here with ``CARRIES_CRYPTO_PROVIDER``.

    ``boundary`` null is the gate's "unclassified": a provider was detected and nobody has
    dispositioned it, which the gate treats as a failure. It is stored, not dropped, so a
    known-unreviewed provider is on the grid instead of absent from it.

    This node holds NO key material, fingerprint or file contents, and has no field that could:
    it records that an implementation is present and what was decided, never what it protects.
    The CycloneDX CBOM (``cryptographic-asset``) models algorithms, protocols, certificates and
    key material; it has no notion of an implementation-level disposition, so none of its fields
    are borrowed here.

    Spec: specs/spec-computing-core-v0.md (req-computing-core-crypto-provider).
    """

    ENTITY_TYPE: ClassVar[str] = "computing_core__crypto_provider"
    ENTITY_NAME: ClassVar[str] = "Crypto Provider"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "A cryptographic implementation found in an artifact (the OpenSSL FIPS provider, a Go "
        "binary's crypto/tls, a Rust crate's aws-lc) and the reviewed decision about it: inside "
        "the FIPS boundary and validated, an unvalidated build, out of boundary, never reached, "
        "or must-fix. Records presence and disposition only, never key material."
    )
    ENTITY_ICON: ClassVar[str] = "crypto-provider"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {"tap.computing": "runtime"}
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("scope", "artifact", "provider")
    DEFAULT_DISPLAY: ClassVar[dict[str, Any]] = {
        "tap_viz": {
            "shape": "diamond",
            "colors": {"fill": "#B5826F", "border": "#82503F", "label": "#FFFFFF"},
        }
    }

    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {
            "nodes": [
                {"type": "computing_core__library"},
                {"type": "computing_core__package"},
                {"type": "computing_core__program"},
            ],
            "edges": [{"type": "CARRIES_CRYPTO_PROVIDER__computing_core"}],
        },
    ]

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "scope": {"type": "string", "minLength": 1},
        "artifact": {"type": "string", "minLength": 1},
        "provider": {"type": "string", "minLength": 1},
        "provider_kind": {"type": "string", "enum": list(CRYPTO_PROVIDER_KINDS)},
        "boundary": {"type": ["string", "null"], "enum": [*CRYPTO_BOUNDARIES, None]},
        "rationale": {"type": "string"},
        "fips_validation": {"type": "string"},
    }
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        "scope": {"validation": "jsonschema", "schema": {"type": "string", "minLength": 1}},
        "artifact": {"validation": "jsonschema", "schema": {"type": "string", "minLength": 1}},
        "provider": {"validation": "jsonschema", "schema": {"type": "string", "minLength": 1}},
        "provider_kind": {
            "validation": "jsonschema",
            "schema": {"type": "string", "enum": list(CRYPTO_PROVIDER_KINDS)},
        },
        "boundary": {
            "validation": "jsonschema",
            "schema": {"type": ["string", "null"], "enum": [*CRYPTO_BOUNDARIES, None]},
        },
        "rationale": {"validation": "jsonschema", "schema": {"type": "string"}},
        "fips_validation": {"validation": "jsonschema", "schema": {"type": "string"}},
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["scope", "artifact", "provider", "provider_kind"]

    scope = models.CharField(
        max_length=255,
        blank=True,
        default="",
        help_text="What was scanned: the image or environment the finding is from (tap-web), or a plugin slug.",
    )
    artifact = models.CharField(
        max_length=1024,
        blank=True,
        default="",
        help_text="Where it was found: an absolute path (/usr/lib/ossl-modules/fips.so), or dist:<name> for an installed distribution.",
    )
    provider = models.CharField(
        max_length=64,
        blank=True,
        default="",
        db_index=True,
        help_text="The implementation, by the crypto-BOM registry's name: openssl-system, go-crypto, rust-aws-lc-rs, libsodium.",
    )
    provider_kind = models.CharField(max_length=24, blank=True, default="", help_text="One of CRYPTO_PROVIDER_KINDS.")
    boundary = models.CharField(  # noqa: DJ001  (req-computing-core-crypto-provider-3)
        max_length=32,
        blank=True,
        null=True,
        default=None,
        db_index=True,
        help_text="One of CRYPTO_BOUNDARIES. Null = detected and not yet dispositioned (the gate's unclassified).",
    )
    rationale = models.TextField(
        blank=True, default="", help_text="Why the boundary was decided; the registry's reviewed sentence."
    )
    fips_validation = models.CharField(
        max_length=512,
        blank=True,
        default="",
        help_text="The validation status of the module as shipped, as a sentence (CMVP certificate, or 'not CMVP-validated as shipped').",
    )

    class Meta(BaseModel.Meta):
        db_table = "computing_core__crypto_provider"

    def get_name(self) -> str:
        return f"{self.provider} ({self.artifact})" if self.artifact else self.provider

    def __str__(self) -> str:
        return self.get_name()
