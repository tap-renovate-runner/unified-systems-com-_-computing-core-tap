"""The outcome of verifying an SBOM's attestation, and the record of a document that was not parsed.

Verification itself (signer identity, subject digest and predicate type) happens in the caller
against its trust list; this module only carries the outcome onto the ``sbom_document`` row and
refuses to read the contents of a document that was not verified (``req-cicd-sbom-22-2`` and
``-22-9``: only ``verified`` is parsed, the other two are recorded, never dropped).

Mapping to the node's tri-state: ``verified`` is ``True``, ``refused`` is ``False`` and
``not-observable`` is ``None``.

Spec: specs/spec-computing-core-v0.md (req-computing-core-sbom-parse-10 and -11).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Final

from tap_plugin.computing_core.sbom.batch import NodeRow, SbomBatch, SbomReport
from tap_plugin.computing_core.sbom.parser import (
    _IMAGE_DIGEST,
    _SERIAL,
    LIMITS,
    SBOM_DOCUMENT,
    SPEC_VERSIONS,
    SbomParseError,
    _load,
)

from tap_grid.natural_key import identity_lock_key

VERIFIED: Final[str] = "verified"
REFUSED: Final[str] = "refused"
NOT_OBSERVABLE: Final[str] = "not-observable"
OUTCOMES: Final[tuple[str, ...]] = (VERIFIED, REFUSED, NOT_OBSERVABLE)

#: The checks a refusal can name (``req-cicd-sbom-22-2``). The note is free text up to its column,
#: because the spec that defines the checks may reword them; these are the names in use today.
SIGNER_IDENTITY: Final[str] = "signer-identity"
SUBJECT_DIGEST: Final[str] = "subject-digest"
PREDICATE_TYPE: Final[str] = "predicate-type"

NOTE_MAX: Final[int] = 255
SIGNER_MAX: Final[int] = 512


@dataclass(frozen=True)
class Verification:
    """What the caller decided about one document: an outcome, the failing check, the signer."""

    outcome: str
    """``verified``, ``refused`` or ``not-observable``."""
    check: str = ""
    """Refused: the failing check, required. Not observable: why, optional. Verified: empty."""
    signer: str = ""
    """The verified signer's identity; only with ``verified``."""

    def __post_init__(self) -> None:
        if self.outcome not in OUTCOMES:
            raise ValueError(f"outcome {self.outcome!r} is not one of {', '.join(OUTCOMES)}")
        if not isinstance(self.check, str) or not isinstance(self.signer, str):
            raise ValueError("check and signer must be strings")
        if self.outcome == REFUSED and not self.check.strip():
            raise ValueError("a refused document names the check that failed")
        if self.outcome == VERIFIED and self.check:
            raise ValueError("a verified document has no failing check")
        if self.outcome != VERIFIED and self.signer:
            raise ValueError("only a verified document records a signer")
        if len(self.check) > NOTE_MAX or len(self.signer) > SIGNER_MAX:
            raise ValueError(f"check is at most {NOTE_MAX} characters and signer at most {SIGNER_MAX}")

    @property
    def verified(self) -> bool | None:
        """The node's tri-state: ``True`` verified, ``False`` refused, ``None`` not observable."""
        return {VERIFIED: True, REFUSED: False, NOT_OBSERVABLE: None}[self.outcome]

    def document_fields(self) -> dict[str, Any]:
        """The three ``sbom_document`` fields this outcome sets."""
        return {"verified": self.verified, "signer": self.signer, "verification_note": self.check.strip()}


def record_document(data: bytes, *, verification: Verification, subject_digest: str = "") -> SbomBatch:
    """A batch holding only the ``sbom_document`` row of a document that was not verified.

    The document's contents are not parsed for packages: no package, library, source package,
    operating-system or edge row is returned, and nothing in the body is trusted. The row carries
    the SHA-256 of the exact bytes, the outcome, and the few identifying fields that are safe to
    read: the format and ``specVersion``, ``serialNumber`` and ``version`` if the body parses as
    CycloneDX JSON within the parser's caps, and left empty if it does not. ``subject_digest`` is
    the caller's (from the attestation it checked), not the body's claim.

    A document that was verified goes through ``parse_cyclonedx`` instead.
    """
    if verification.outcome == VERIFIED:
        raise ValueError("a verified document is parsed with parse_cyclonedx, not only recorded")
    if subject_digest and not _IMAGE_DIGEST.match(subject_digest):
        raise ValueError(f"subject_digest {subject_digest!r} is not <algorithm>:<hex>")
    digest = hashlib.sha256(bytes(data)).hexdigest()
    fmt, spec_version, serial, revision = "unknown", "", "", 1
    try:
        body = _load(data)
    except SbomParseError:
        body = {}
    if body.get("bomFormat") == "CycloneDX":
        fmt = "cyclonedx"
        spec = body.get("specVersion")
        spec_version = spec if spec in SPEC_VERSIONS else ""
        stated = body.get("serialNumber")
        serial = stated if isinstance(stated, str) and _SERIAL.match(stated) else ""
        number = body.get("version")
        if isinstance(number, int) and not isinstance(number, bool) and 1 <= number <= LIMITS["revision"]:
            revision = number
    label = identity_lock_key(SBOM_DOCUMENT, {"content_digest": digest})
    if label is None:  # pragma: no cover - the digest is never a hole
        raise SbomParseError("the document has no digest")
    row = NodeRow(
        ref=label,
        entity_type=SBOM_DOCUMENT,
        name=f"sbom {digest[:12]} r{revision}",
        properties={
            "content_digest": digest,
            "format": fmt,
            "spec_version": spec_version,
            "serial_number": serial,
            "revision": revision,
            "subject_digest": subject_digest,
            "produced_at": None,
            "generator": "",
            "component_count": 0,
            **verification.document_fields(),
        },
    )
    note = f"recorded without parsing: {verification.outcome}" + (
        f" ({verification.check})" if verification.check else ""
    )
    return SbomBatch(nodes=(row,), edges=(), report=SbomReport(component_count=0, notes=(note,)))
