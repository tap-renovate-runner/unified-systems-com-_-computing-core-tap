"""Read the ``vulnerabilities[]`` of a verified CycloneDX document, purely.

``parse_cyclonedx_vulnerabilities(data, verification=...)`` takes the exact bytes of a CycloneDX
document the caller has verified and returns a ``VulnerabilityBatch``: the vulnerabilities the
document names, the (vulnerability x component) matches, the tools that detected them and a report
of what was skipped. It is the twin of ``parse_cyclonedx`` (the same gate, the same caps, the same
rule for which grid node a component is) and shares its guarantees: no Django, no file, no socket,
no clock, the same bytes giving the same batch anywhere.

What it does NOT do is name a compliance vocabulary. The records are neutral: a vulnerability is
what the document says about one public id, a match is that id affecting one component, and a
component is named by the natural key of the ``computing_core`` node it becomes. Turning them into
findings, scanners and edges is the job of whoever owns that vocabulary (github_core writes
``compliance_core`` from them), so this plugin takes no dependency on it.

**Absent is not empty.** A document with no ``vulnerabilities`` key was never scanned (revision 1 of
an image's SBOM): it is refused, because an empty batch would read as "no vulnerabilities". A
document with ``"vulnerabilities": []`` was scanned and found nothing, and returns an empty batch.
Inside a record, ``None`` is "the document does not say" and an empty value is "it looked and found
none": a fact is never filled in from outside the document.

Spec: specs/spec-computing-core-v0.md (req-computing-core-sbom-vulns).
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import TYPE_CHECKING, Any, Final

from tap_plugin.computing_core.sbom.parser import (
    _IMAGE_DIGEST,
    _SERIAL,
    _TIMESTAMP,
    LIBRARY,
    OPERATING_SYSTEM,
    PACKAGE,
    SbomParseError,
    _clip,
    _flatten,
    _load,
    _check_format,
    _text,
    classify_component,
    require_verified,
)

if TYPE_CHECKING:
    from tap_plugin.computing_core.sbom.verification import Verification

#: Most ``vulnerabilities`` entries accepted. The tap-web document has 94; a document over the cap is
#: refused, never truncated.
MAX_VULNERABILITIES: Final[int] = 100_000
#: The longest ``vuln_id`` a ``compliance_vulnerability`` accepts (its column), restated because the model
#: lives in another plugin. An entry with a longer id is skipped with a report note, never cut.
MAX_VULN_ID: Final[int] = 128

#: CycloneDX rating methods that carry a CVSS score, and the CVSS version each names.
_CVSS_VERSION: Final[Mapping[str, str]] = {"CVSSv2": "2.0", "CVSSv3": "3.0", "CVSSv31": "3.1", "CVSSv4": "4.0"}
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

#: ``analysis.state`` values (CycloneDX) that say the component is not exposed to the vulnerability.
NOT_AFFECTED_STATES: Final[frozenset[str]] = frozenset(
    {"resolved", "resolved_with_pedigree", "false_positive", "not_affected"}
)

_KIND_TYPE: Final[Mapping[str, str]] = {"package": PACKAGE, "library": LIBRARY, "os": OPERATING_SYSTEM}
_KEY_FIELDS: Final[Mapping[str, tuple[str, str, str]]] = {
    "package": ("ecosystem", "name", "version"),
    "library": ("ecosystem", "name", "version"),
    "os": ("os_id", "version_id", "build_id"),
}


@dataclass(frozen=True)
class ComponentKey:
    """The ``computing_core`` node a component is, by its natural key (the grid finds the row by it)."""

    entity_type: str
    """``computing_core__package``, ``computing_core__library`` or ``computing_core__operating_system``."""
    values: tuple[str, str, str]
    """The natural-key values in the order of ``fields``."""
    fields: tuple[str, str, str]
    """The natural-key field names of ``entity_type``."""
    name: str
    version: str
    bom_ref: str
    """The document-local handle the vulnerability named it by; stored nowhere, kept for the report."""
    purl: str

    @property
    def key(self) -> dict[str, str]:
        """The natural key as ``{field: value}``."""
        return dict(zip(self.fields, self.values, strict=True))

    @property
    def label(self) -> str:
        """A stable text for the component: ``ecosystem/name@version`` (``os_id/version_id`` for a system)."""
        if self.entity_type == OPERATING_SYSTEM:
            return f"{self.values[0]}@{self.values[1]}"
        return f"{self.values[0]}/{self.values[1]}@{self.values[2]}"


@dataclass(frozen=True)
class Cvss:
    score: float
    vector: str | None
    version: str
    source: str


@dataclass(frozen=True)
class Ssvc:
    exploitation: str | None
    automatable: str | None
    technical_impact: str | None
    assessed_at: str | None
    version: str | None


@dataclass(frozen=True)
class Kev:
    """CISA's Known Exploited Vulnerabilities answer. ``listed`` None means the catalog was not read."""

    listed: bool | None
    catalog_version: str | None = None
    date_added: str | None = None
    due_date: str | None = None
    required_action: str | None = None
    ransomware_use: str | None = None


@dataclass(frozen=True)
class Epss:
    score: float
    percentile: float | None
    date: str | None


@dataclass(frozen=True)
class Advisory:
    """A public record of the id that the entry links (``advisories[]``), titled as CI titles it."""

    title: str
    url: str


@dataclass(frozen=True)
class VulnerabilityRecord:
    """What a document says about one public vulnerability id. ``None`` is "not said", never a default."""

    vuln_id: str
    aliases: tuple[str, ...] | None
    """Every other id the entries list for it; ``()`` when the entries list none."""
    description: str | None
    title: str | None
    """``tap:title``: the record's title, else the advisory's, as CI cut it (it may end in ``...``)."""
    published_at: str | None
    """The entry's ``published``: the CVE record's date, else the advisory's."""
    advisories: tuple[Advisory, ...]
    """Every ``advisories[]`` link the entries give, in a stable order; ``()`` when none."""
    cvss: Cvss | None
    cwes: tuple[str, ...] | None
    """``CWE-<n>`` ids. ``()`` only when the CVE record was read and lists none; None when no source looked."""
    ssvc: Ssvc | None
    kev: Kev | None
    epss: Epss | None
    record_updated_at: str | None
    """When the record says it was last modified: the entry's ``updated``, else ``tap:cve-record:date-updated``."""
    source_url: str | None
    """The entry's ``source.url``: the scanner's own record of the id. NOT proof of where the CVE record came from."""

    @property
    def record_url(self) -> str | None:
        """Where the public record is: the ``CVE Record`` advisory, else the first other advisory, else None."""
        for advisory in self.advisories:
            if advisory.title == "CVE Record":
                return advisory.url
        return self.advisories[0].url if self.advisories else None


@dataclass(frozen=True)
class Detector:
    """A tool the document names as having reported matches, as it names itself."""

    name: str
    version: str | None


@dataclass(frozen=True)
class VulnerabilityMatch:
    """One vulnerability affecting one component, as one entry of the document says."""

    vuln_id: str
    component: ComponentKey
    affected_version: str | None
    fixed_versions: tuple[str, ...] | None
    """Versions that fix it in this component. ``()`` when the scanner said no fix exists; None when unknown."""
    fix_state: str | None
    analysis_state: str | None
    """CycloneDX ``analysis.state`` when the entry carries one (a VEX statement); None otherwise."""
    detectors: tuple[Detector, ...]

    @property
    def exposed(self) -> bool:
        """False when the entry's own analysis says the component is not exposed (``NOT_AFFECTED_STATES``)."""
        return self.analysis_state not in NOT_AFFECTED_STATES


@dataclass(frozen=True)
class DocumentInfo:
    """Which document and which scan this batch came from."""

    content_digest: str
    """SHA-256 of the exact bytes passed in; the same value ``parse_cyclonedx`` puts on ``sbom_document``."""
    serial_number: str | None
    revision: int
    subject_name: str | None
    """The image the document describes (``metadata.component.name``)."""
    subject_digest: str | None
    produced_at: str | None
    previous_content_digest: str | None
    """``tap:revision:previous-content-digest``: the revision this one was made from."""
    scanner_db_built: str | None
    signer: str
    """The verified signer the caller's ``Verification`` named (never read from the document itself)."""


@dataclass(frozen=True)
class VulnerabilityReport:
    """What was counted, skipped and chosen, so nothing is dropped silently."""

    entries: int
    """``vulnerabilities`` entries the document lists."""
    skipped_entries: Mapping[str, int] = field(default_factory=dict)
    """Reason -> count for entries that became no record."""
    skipped_matches: Mapping[str, int] = field(default_factory=dict)
    """Reason -> count for ``affects`` that became no match (names an unlisted component, a skipped one, ...)."""
    duplicate_matches_collapsed: int = 0
    """Matches that named a (vulnerability, component node) an earlier one already named."""
    notes: tuple[str, ...] = ()
    """Values left out or entries that disagreed, each with its reason."""


@dataclass(frozen=True)
class VulnerabilityBatch:
    """Everything one verified document says about vulnerabilities: rows sorted so equal input is equal output."""

    document: DocumentInfo
    vulnerabilities: tuple[VulnerabilityRecord, ...]
    matches: tuple[VulnerabilityMatch, ...]
    detectors: tuple[Detector, ...]
    report: VulnerabilityReport

    def matches_of(self, vuln_id: str) -> tuple[VulnerabilityMatch, ...]:
        return tuple(m for m in self.matches if m.vuln_id == vuln_id)

    def unmatched_vulnerabilities(self) -> tuple[str, ...]:
        """Ids of records that no match names (every entry's ``affects`` was skipped)."""
        named = {m.vuln_id for m in self.matches}
        return tuple(v.vuln_id for v in self.vulnerabilities if v.vuln_id not in named)


# --- small readers ----------------------------------------------------------------------------


def _props(entry: Mapping[str, Any]) -> dict[str, str]:
    """First value per property name of an entry (or of the document's metadata)."""
    found: dict[str, str] = {}
    raw = entry.get("properties")
    for prop in raw if isinstance(raw, list) else []:
        if isinstance(prop, dict):
            name, value = _text(prop.get("name")), prop.get("value")
            if name and isinstance(value, str):
                found.setdefault(name, value)
    return found


def _stamp(value: str | None, notes: list[str], who: str, what: str) -> str | None:
    """An RFC 3339 date-time with a zone, else None with a note (the shape ``format: date-time`` accepts)."""
    if not value:
        return None
    if _TIMESTAMP.fullmatch(value):
        try:
            datetime.fromisoformat(value)
            return value
        except ValueError:
            pass
    notes.append(f"{who}: {what} {_clip(value)} is not an RFC 3339 date-time with a zone; left out")
    return None


def _day(value: str | None, notes: list[str], who: str, what: str) -> str | None:
    """A calendar date ``YYYY-MM-DD``, else None with a note."""
    if not value:
        return None
    if _DATE.fullmatch(value):
        try:
            date.fromisoformat(value)
            return value
        except ValueError:
            pass
    notes.append(f"{who}: {what} {_clip(value)} is not a YYYY-MM-DD date; left out")
    return None


def _number(value: object, low: float, high: float) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float | str):
        return None
    try:
        number = float(value)
    except ValueError:
        return None
    return number if low <= number <= high else None


def _cvss(ratings: list[Mapping[str, Any]]) -> Cvss | None:
    """The CVSS rating to show: the newest CVSS version listed, its highest score, then the source name.

    The entry lists every CVSS rating the scanner and the CVE record gave (one per source and version);
    the node holds one, so the choice is made by a rule that reads the document and nothing else.
    """
    candidates: list[Cvss] = []
    for rating in ratings:
        version = _CVSS_VERSION.get(_text(rating.get("method")))
        score = _number(rating.get("score"), 0.0, 10.0)
        source = rating.get("source")
        source_name = _text(source.get("name")) if isinstance(source, dict) else ""
        if version is None or score is None or not source_name:
            continue
        candidates.append(
            Cvss(score=score, vector=_text(rating.get("vector")) or None, version=version, source=source_name)
        )
    if not candidates:
        return None
    return min(candidates, key=lambda c: (-float(c.version), -c.score, c.source))


def _epss(ratings: list[Mapping[str, Any]], props: Mapping[str, str], notes: list[str], who: str) -> Epss | None:
    for rating in ratings:
        source = rating.get("source")
        if isinstance(source, dict) and _text(source.get("name")) == "FIRST" and rating.get("justification") == "EPSS":
            score = _number(rating.get("score"), 0.0, 1.0)
            if score is None:
                notes.append(f"{who}: EPSS score {_clip(rating.get('score'))} is not a probability; left out")
                return None
            return Epss(
                score=score,
                percentile=_number(props.get("tap:epss:percentile"), 0.0, 1.0),
                date=_day(props.get("tap:epss:date"), notes, who, "EPSS date"),
            )
    return None


def _ssvc(props: Mapping[str, str], notes: list[str], who: str) -> Ssvc | None:
    if not any(name.startswith("tap:ssvc:") for name in props):
        return None
    return Ssvc(
        exploitation=props.get("tap:ssvc:exploitation") or None,
        automatable=props.get("tap:ssvc:automatable") or None,
        technical_impact=props.get("tap:ssvc:technical-impact") or None,
        assessed_at=_stamp(props.get("tap:ssvc:assessed-at"), notes, who, "SSVC assessment time"),
        version=props.get("tap:ssvc:version") or None,
    )


def _kev(props: Mapping[str, str], doc_props: Mapping[str, str], notes: list[str], who: str) -> Kev | None:
    answer = props.get("tap:kev:listed")
    if answer == "true":
        return Kev(
            listed=True,
            catalog_version=props.get("tap:kev:catalog-version") or doc_props.get("tap:kev:catalog-version") or None,
            date_added=_day(props.get("tap:kev:date-added"), notes, who, "KEV date added"),
            due_date=_day(props.get("tap:kev:due-date"), notes, who, "KEV due date"),
            required_action=props.get("tap:kev:required-action") or None,
            ransomware_use=props.get("tap:kev:ransomware-use") or None,
        )
    if answer == "false":
        return Kev(listed=False, catalog_version=doc_props.get("tap:kev:catalog-version") or None)
    return None  # "not-observed", absent, or anything else: the catalog was not read


def _cwes(entry: Mapping[str, Any], props: Mapping[str, str]) -> tuple[str, ...] | None:
    raw = entry.get("cwes")
    found = (
        sorted({f"CWE-{n}" for n in raw if isinstance(n, int) and not isinstance(n, bool) and n >= 0})
        if isinstance(raw, list)
        else []
    )
    if found:
        return tuple(found)
    # An empty list is "no CWE" only when the CVE record was read; otherwise nothing looked.
    return () if props.get("tap:cve-record:status") == "observed" else None


def _fix(props: Mapping[str, str]) -> tuple[tuple[str, ...] | None, str | None]:
    state = props.get("tap:fix:state") or None
    listed = props.get("tap:fix:versions")
    if listed:
        return tuple(sorted(v for v in listed.split(",") if v)), state
    if state in ("not-fixed", "wont-fix"):
        return (), state
    return None, state


def _detectors(entry: Mapping[str, Any]) -> tuple[Detector, ...]:
    tools = entry.get("tools")
    items = tools.get("components") if isinstance(tools, dict) else tools
    found: dict[tuple[str, str | None], Detector] = {}
    for tool in items if isinstance(items, list) else []:
        if isinstance(tool, dict) and _text(tool.get("name")):
            detector = Detector(name=_text(tool["name"]), version=_text(tool.get("version")) or None)
            found[(detector.name, detector.version)] = detector
    return tuple(found[k] for k in sorted(found, key=lambda k: (k[0], k[1] or "")))


# --- the parser -------------------------------------------------------------------------------


def parse_cyclonedx_vulnerabilities(data: bytes, *, verification: Verification) -> VulnerabilityBatch:
    """Read the vulnerabilities of one CycloneDX 1.4 to 1.7 JSON document the caller has verified.

    ``data`` is the document's exact bytes. ``verification`` is REQUIRED and only a ``verified``
    outcome is read (``require_verified``): omitting it is a ``TypeError``, any other outcome a
    ``ValueError`` before a byte of the body is read, exactly as for ``parse_cyclonedx``.
    Raises ``SbomParseError`` for an unreadable document and for one with no ``vulnerabilities`` key
    (never scanned); a scanned document with no vulnerabilities returns an empty batch.
    """
    require_verified(verification)
    document = _load(data)
    _check_format(document)
    components, _ = _flatten(document)

    raw_vulns = document.get("vulnerabilities")
    if raw_vulns is None:
        raise SbomParseError(
            "the document carries no vulnerabilities array: it was never scanned, which is not the same as "
            "having no vulnerabilities"
        )
    if not isinstance(raw_vulns, list):
        raise SbomParseError("the document's vulnerabilities is not an array")
    if len(raw_vulns) > MAX_VULNERABILITIES:
        raise SbomParseError(f"the document lists more than {MAX_VULNERABILITIES} vulnerabilities, over the cap")

    notes: list[str] = []
    refs: dict[str, Mapping[str, Any]] = {}
    for component in components:
        bom_ref = component.get("bom-ref")
        if isinstance(bom_ref, str) and bom_ref:
            if bom_ref in refs:
                raise SbomParseError(f"bom-ref {bom_ref!r} names two components, so a vulnerability on it is ambiguous")
            refs[bom_ref] = component

    raw_metadata = document.get("metadata")
    metadata: Mapping[str, Any] = raw_metadata if isinstance(raw_metadata, dict) else {}
    doc_props = _props(metadata)
    raw_subject = metadata.get("component")
    subject: Mapping[str, Any] = raw_subject if isinstance(raw_subject, dict) else {}
    subject_version = _text(subject.get("version"))
    serial = _text(document.get("serialNumber"))
    revision = document.get("version")
    produced = _stamp(_text(metadata.get("timestamp")) or None, notes, "metadata", "timestamp")
    info = DocumentInfo(
        content_digest=hashlib.sha256(bytes(data)).hexdigest(),
        serial_number=serial if _SERIAL.fullmatch(serial) else None,
        revision=revision if isinstance(revision, int) and not isinstance(revision, bool) and revision >= 1 else 1,
        subject_name=_text(subject.get("name")) or None,
        subject_digest=subject_version if _IMAGE_DIGEST.fullmatch(subject_version) else None,
        produced_at=produced,
        previous_content_digest=doc_props.get("tap:revision:previous-content-digest") or None,
        scanner_db_built=_stamp(
            doc_props.get("tap:scan:grype-db-built"), notes, "metadata", "scanner database build time"
        ),
        signer=verification.signer,
    )

    skipped_entries: Counter[str] = Counter()
    skipped_matches: Counter[str] = Counter()
    duplicates = 0
    by_id: dict[str, list[Mapping[str, Any]]] = {}
    matches: dict[tuple[str, str, tuple[str, str, str]], VulnerabilityMatch] = {}
    all_detectors: dict[tuple[str, str | None], Detector] = {}

    for entry in raw_vulns:
        if not isinstance(entry, dict):
            skipped_entries["entry is not an object"] += 1
            continue
        vuln_id = _text(entry.get("id"))
        if not vuln_id:
            skipped_entries["no id"] += 1
            continue
        if len(vuln_id) > MAX_VULN_ID:
            skipped_entries[f"id longer than {MAX_VULN_ID} characters"] += 1
            continue
        by_id.setdefault(vuln_id, []).append(entry)
        props = _props(entry)
        fix_versions, fix_state = _fix(props)
        analysis = entry.get("analysis")
        analysis_state = _text(analysis.get("state")) or None if isinstance(analysis, dict) else None
        detectors = _detectors(entry)
        for detector in detectors:
            all_detectors[(detector.name, detector.version)] = detector
        affects = entry.get("affects")
        if not isinstance(affects, list) or not affects:
            skipped_matches["entry affects no component"] += 1
            continue
        for affect in affects:
            ref = _text(affect.get("ref")) if isinstance(affect, dict) else ""
            component = refs.get(ref)
            if component is None:
                skipped_matches["affects names no listed component"] += 1
                continue
            classified = classify_component(component, notes)
            if classified.skip:
                skipped_matches[f"affects a component that becomes no node ({classified.skip})"] += 1
                continue
            affected_version: str | None = None
            versions = affect.get("versions") if isinstance(affect, dict) else None
            if isinstance(versions, list) and versions:
                listed = [v for v in versions if isinstance(v, dict) and _text(v.get("status")) in ("affected", "")]
                if not listed:
                    skipped_matches["affects lists no affected version"] += 1
                    continue
                affected_version = _text(listed[0].get("version")) or None
            key = (vuln_id, _KIND_TYPE[classified.kind], classified.key)
            if key in matches:
                duplicates += 1
                continue
            matches[key] = VulnerabilityMatch(
                vuln_id=vuln_id,
                component=ComponentKey(
                    entity_type=_KIND_TYPE[classified.kind],
                    values=classified.key,
                    fields=_KEY_FIELDS[classified.kind],
                    name=_text(component.get("name")),
                    version=_text(component.get("version")),
                    bom_ref=ref,
                    purl=_text(component.get("purl")),
                ),
                affected_version=affected_version,
                fixed_versions=fix_versions,
                fix_state=fix_state,
                analysis_state=analysis_state,
                detectors=detectors,
            )

    records = tuple(_record(vuln_id, by_id[vuln_id], doc_props, notes) for vuln_id in sorted(by_id))
    ordered_matches = tuple(
        sorted(matches.values(), key=lambda m: (m.vuln_id, m.component.entity_type, m.component.values))
    )
    return VulnerabilityBatch(
        document=info,
        vulnerabilities=records,
        matches=ordered_matches,
        detectors=tuple(all_detectors[k] for k in sorted(all_detectors, key=lambda k: (k[0], k[1] or ""))),
        report=VulnerabilityReport(
            entries=len(raw_vulns),
            skipped_entries=dict(sorted(skipped_entries.items())),
            skipped_matches=dict(sorted(skipped_matches.items())),
            duplicate_matches_collapsed=duplicates,
            notes=tuple(sorted(set(notes))),
        ),
    )


def _record(
    vuln_id: str, entries: list[Mapping[str, Any]], doc_props: Mapping[str, str], notes: list[str]
) -> VulnerabilityRecord:
    """One record from every entry that names the id (one per affected component).

    The facts are the id's, not the component's, so the entries should agree; where they do not the
    rule is stated rather than hidden: ratings are pooled, a KEV listing wins over its absence, and
    every other fact is the first one given in the order of the entry's first affected ``bom-ref``.
    """
    ordered = sorted(entries, key=lambda e: _first_ref(e))
    ratings: list[Mapping[str, Any]] = []
    aliases: set[str] = set()
    cwes: set[str] = set()
    cwes_observed = False
    descriptions: list[str] = []
    ssvcs: list[Ssvc] = []
    kevs: list[Kev] = []
    epsses: list[Epss] = []
    updated: list[str] = []
    urls: list[str] = []
    titles: list[str] = []
    published: list[str] = []
    advisories: dict[tuple[str, str], Advisory] = {}
    for entry in ordered:
        props = _props(entry)
        raw_ratings = entry.get("ratings")
        own_ratings = [r for r in raw_ratings if isinstance(r, dict)] if isinstance(raw_ratings, list) else []
        ratings += own_ratings
        refs = entry.get("references")
        aliases |= (
            {_text(r.get("id")) for r in refs if isinstance(r, dict) and _text(r.get("id"))}
            if isinstance(refs, list)
            else set()
        )
        found = _cwes(entry, props)
        if found is not None:
            cwes_observed = True
            cwes |= set(found)
        if _text(entry.get("description")):
            descriptions.append(_text(entry["description"]))
        ssvc = _ssvc(props, notes, vuln_id)
        if ssvc is not None:
            ssvcs.append(ssvc)
        kev = _kev(props, doc_props, notes, vuln_id)
        if kev is not None:
            kevs.append(kev)
        epss = _epss(own_ratings, props, notes, vuln_id)
        if epss is not None:
            epsses.append(epss)
        stamp = _stamp(
            _text(entry.get("updated")) or props.get("tap:cve-record:date-updated"),
            notes,
            vuln_id,
            "record update time",
        )
        if stamp:
            updated.append(stamp)
        when = _stamp(_text(entry.get("published")) or None, notes, vuln_id, "publication time")
        if when:
            published.append(when)
        if props.get("tap:title"):
            titles.append(props["tap:title"])
        links = entry.get("advisories")
        for link in links if isinstance(links, list) else []:
            if isinstance(link, dict) and _text(link.get("title")) and _text(link.get("url")):
                advisory = Advisory(_text(link["title"]), _text(link["url"]))
                advisories[(advisory.title, advisory.url)] = advisory
        source = entry.get("source")
        if isinstance(source, dict) and _text(source.get("url")):
            urls.append(_text(source["url"]))
    aliases.discard(vuln_id)
    for label, values in (("description", descriptions), ("title", titles), ("publication time", published), ("SSVC assessment", ssvcs), ("EPSS score", epsses)):
        if len({repr(v) for v in values}) > 1:
            notes.append(f"{vuln_id}: its entries disagree on the {label}; the first is kept")
    kev_chosen = next((k for k in kevs if k.listed), kevs[0] if kevs else None)
    if len({k.listed for k in kevs}) > 1:
        notes.append(f"{vuln_id}: its entries disagree on the KEV listing; the listing is kept")
    return VulnerabilityRecord(
        vuln_id=vuln_id,
        aliases=tuple(sorted(aliases)),
        description=descriptions[0] if descriptions else None,
        title=titles[0] if titles else None,
        published_at=published[0] if published else None,
        advisories=tuple(advisories[k] for k in sorted(advisories)),
        cvss=_cvss(ratings),
        cwes=tuple(sorted(cwes, key=lambda c: int(c[4:]))) if cwes_observed else None,
        ssvc=ssvcs[0] if ssvcs else None,
        kev=kev_chosen,
        epss=epsses[0] if epsses else None,
        record_updated_at=updated[0] if updated else None,
        source_url=urls[0] if urls else None,
    )


def _first_ref(entry: Mapping[str, Any]) -> str:
    """The first ``affects`` ref of an entry, to order a vulnerability's entries deterministically."""
    affects = entry.get("affects")
    first = affects[0] if isinstance(affects, list) and affects else None
    return _text(first.get("ref")) if isinstance(first, dict) else ""
