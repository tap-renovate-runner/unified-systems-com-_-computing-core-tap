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
import re
from dataclasses import dataclass
from typing import Any, Final

from tap_plugin.computing_core.sbom.batch import NodeRow, SbomBatch, SbomReport
from tap_plugin.computing_core.sbom.parser import _IMAGE_DIGEST, SBOM_DOCUMENT

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

#: A control character or newline: never in a check or a signer, which end up in a log line and a column.
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
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
        if _CONTROL.search(self.check) or _CONTROL.search(self.signer):
            raise ValueError("check and signer contain no control character or newline")
        if self.outcome == REFUSED and not self.check.strip():
            raise ValueError("a refused document names the check that failed")
        if self.outcome == VERIFIED and not self.signer.strip():
            raise ValueError("a verified document names its signer")
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

    Nothing in the body is read: not parsed as JSON, not scanned (``req-cicd-sbom-24-6``: nothing
    from the contents of an unverified document is parsed). The row is the SHA-256 of the exact
    bytes, the caller's outcome (``verified`` false for ``refused``, null for ``not-observable``),
    the failing check in ``verification_note``, and the caller's ``subject_digest`` (from the
    attestation it checked). ``format`` is ``unknown`` and ``spec_version``, ``serial_number`` and
    ``component_count`` are empty or zero, with ``revision`` 1, whatever the body is, so a readable
    and an unreadable body give the same row apart from the digest. No package, library,
    source-package, operating-system or edge row is returned.

    ``data`` must be ``bytes`` or ``bytearray``: anything else is a ``TypeError`` (``bytes(5)``
    would hash five zero bytes). A verified document goes through ``parse_cyclonedx`` instead.
    """
    if not isinstance(data, bytes | bytearray):
        raise TypeError(f"the document must be bytes, not {type(data).__name__}")
    if not isinstance(verification, Verification):
        raise TypeError("verification must be a Verification")
    if verification.outcome == VERIFIED:
        raise ValueError("a verified document is parsed with parse_cyclonedx, not only recorded")
    if not isinstance(subject_digest, str) or (subject_digest and not _IMAGE_DIGEST.fullmatch(subject_digest)):
        raise ValueError("subject_digest must be empty or <algorithm>:<hex>")
    digest = hashlib.sha256(bytes(data)).hexdigest()
    label = identity_lock_key(SBOM_DOCUMENT, {"content_digest": digest})
    if label is None:  # pragma: no cover - the digest is never a hole
        raise ValueError("the document has no digest")
    row = NodeRow(
        ref=label,
        entity_type=SBOM_DOCUMENT,
        name=f"sbom {digest[:12]} r1",
        properties={
            "content_digest": digest,
            "format": "unknown",
            "spec_version": "",
            "serial_number": "",
            "revision": 1,
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
