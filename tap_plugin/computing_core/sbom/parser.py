"""Parse one CycloneDX JSON document into the grid's software inventory, purely.

``parse_cyclonedx(data, host_id=...)`` takes the document's exact bytes and returns an
``SbomBatch``: package, library, source-package, operating-system and ``sbom_document`` rows and the
edges between them. It imports no Django, opens no file or socket and reads no clock, so the same
bytes give the same batch anywhere. Input is untrusted: size, nesting and component count are
capped and a document over a cap is refused naming the cap, never truncated; a document the parser
cannot read raises ``SbomParseError`` and never returns an empty batch, because an empty batch
reads as "this host has no software".

Entity ids: the grid assigns them and finds a row again by its natural key, so no id can be
derived here. Rows carry a batch-local ``ref`` (the grid's ``identity_lock_key`` over the type and
the natural-key values, a label that never becomes an id) and the importer resolves it.

Spec: specs/spec-computing-core-v0.md (req-computing-core-sbom-parse).
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any, Final
from urllib.parse import unquote

from tap_plugin.computing_core.sbom.batch import EdgeRow, NodeRow, SbomBatch, SbomReport

from tap_grid.natural_key import identity_lock_key

#: Largest document accepted, in bytes. A document over it is refused, not truncated.
MAX_BYTES: Final[int] = 32 * 1024 * 1024
#: Deepest JSON nesting accepted. Real CycloneDX is under 10; 64 leaves room for nested components.
MAX_DEPTH: Final[int] = 64
#: Most components accepted, nested ones included.
MAX_COMPONENTS: Final[int] = 50_000
#: Most ``dependsOn`` entries accepted in total.
MAX_DEPENDENCIES: Final[int] = 500_000

#: The CycloneDX versions read (req-computing-core-sbom-parse-7).
SPEC_VERSIONS: Final[frozenset[str]] = frozenset({"1.4", "1.5", "1.6", "1.7"})

#: Purl types that become a ``package``: something a package manager installs.
PACKAGE_PURL_TYPES: Final[frozenset[str]] = frozenset(
    {"apk", "deb", "rpm", "pypi", "npm", "golang", "cargo", "gem", "maven", "nuget"}
)
#: Purl types that become a ``library``: built or vendored outside a package manager.
LIBRARY_PURL_TYPES: Final[frozenset[str]] = frozenset({"generic", "github"})
#: With no purl, a component of these CycloneDX types is a library; anything else is not software.
LIBRARY_COMPONENT_TYPES: Final[frozenset[str]] = frozenset({"library", "framework", "application"})

#: ``Library.source_kind`` vocabulary (models/library.py LIBRARY_SOURCE_KINDS), restated because the
#: model module imports Django.
SOURCE_KINDS: Final[frozenset[str]] = frozenset({"self-built", "source-built", "copied-image"})

_SERIAL = re.compile(r"^urn:uuid:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_IMAGE_DIGEST = re.compile(r"^[a-z0-9]+:[0-9a-f]{32,}$")
_ARCHITECTURE = re.compile(r"^[A-Za-z0-9_.-]+$")

PACKAGE = "computing_core__package"
LIBRARY = "computing_core__library"
SOURCE_PACKAGE = "computing_core__source_package"
OPERATING_SYSTEM = "computing_core__operating_system"
SBOM_DOCUMENT = "computing_core__sbom_document"
HOST = "computing_core__host"

INSTALLS_PACKAGE = "INSTALLS_PACKAGE__computing_core"
RUNS_OPERATING_SYSTEM = "RUNS_OPERATING_SYSTEM__computing_core"
DERIVES_FROM_SOURCE_PACKAGE = "DERIVES_FROM_SOURCE_PACKAGE__computing_core"
REQUIRES_PACKAGE = "REQUIRES_PACKAGE__computing_core"
DESCRIBES_HOST = "DESCRIBES_HOST__computing_core"


class SbomParseError(ValueError):
    """The document could not be read as CycloneDX; the message says why. Never an empty batch."""


# --- reading the bytes ------------------------------------------------------------------------


def _reject_constant(name: str) -> Any:
    raise SbomParseError(f"not JSON: the document contains {name}, which JSON does not allow")


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise SbomParseError(f"not an unambiguous document: the key {key!r} appears twice in one object")
        seen[key] = value
    return seen


def _depth(value: Any) -> int:
    """Nesting depth of a parsed JSON value, iteratively (a recursive walk is the thing being capped)."""
    deepest = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        item, level = stack.pop()
        if isinstance(item, dict):
            children: Sequence[Any] = list(item.values())
        elif isinstance(item, list):
            children = item
        else:
            continue
        deepest = max(deepest, level)
        stack.extend((child, level + 1) for child in children)
    return deepest


def _load(data: bytes) -> dict[str, Any]:
    if not isinstance(data, bytes | bytearray):
        raise SbomParseError(f"the document must be bytes, not {type(data).__name__}")
    if len(data) > MAX_BYTES:
        raise SbomParseError(f"the document is {len(data)} bytes, over the {MAX_BYTES}-byte size cap")
    if not data.strip():
        raise SbomParseError("the document is empty")
    try:
        document = json.loads(bytes(data), object_pairs_hook=_no_duplicate_keys, parse_constant=_reject_constant)
    except RecursionError:
        raise SbomParseError(f"the document is nested deeper than the {MAX_DEPTH}-level depth cap") from None
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SbomParseError(f"not JSON: {exc}") from None
    depth = _depth(document)
    if depth > MAX_DEPTH:
        raise SbomParseError(f"the document is nested {depth} levels deep, over the {MAX_DEPTH}-level depth cap")
    if not isinstance(document, dict):
        raise SbomParseError(f"not a CycloneDX document: the top level is {type(document).__name__}, not an object")
    return document


def _check_format(document: Mapping[str, Any]) -> str:
    if "spdxVersion" in document or str(document.get("SPDXID", "")).startswith("SPDXRef"):
        raise SbomParseError("the document is SPDX; only CycloneDX 1.4 to 1.7 is read")
    if document.get("bomFormat") != "CycloneDX":
        raise SbomParseError(f"not a CycloneDX document: bomFormat is {document.get('bomFormat')!r}")
    spec_version = document.get("specVersion")
    if spec_version not in SPEC_VERSIONS:
        raise SbomParseError(
            f"CycloneDX specVersion {spec_version!r} is not read; only {', '.join(sorted(SPEC_VERSIONS))} are"
        )
    return str(spec_version)


def _flatten(document: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Every component, nested ones included, in document order, capped at ``MAX_COMPONENTS``."""
    top = document.get("components")
    if not isinstance(top, list):
        raise SbomParseError("the document lists no components array")
    found: list[Mapping[str, Any]] = []
    stack: list[Any] = list(reversed(top))
    while stack:
        item = stack.pop()
        if not isinstance(item, dict):
            raise SbomParseError("a component is not an object")
        found.append(item)
        if len(found) > MAX_COMPONENTS:
            raise SbomParseError(f"the document lists more than {MAX_COMPONENTS} components, over the component cap")
        nested = item.get("components")
        if isinstance(nested, list):
            stack.extend(reversed(nested))
    if not found:
        raise SbomParseError("the document lists no components; an empty inventory is refused, not returned")
    return found


# --- reading a component ----------------------------------------------------------------------


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _properties(component: Mapping[str, Any]) -> tuple[dict[str, str], list[str]]:
    """First value per property name, and the document-order list of ``syft:cpe23`` values."""
    first: dict[str, str] = {}
    cpes: list[str] = []
    for prop in component.get("properties") or []:
        if not isinstance(prop, dict):
            continue
        name, value = _text(prop.get("name")), prop.get("value")
        if not name or not isinstance(value, str):
            continue
        if name == "syft:cpe23":
            cpes.append(value.strip())
        first.setdefault(name, value)
    return first, cpes


def _purl_parts(purl: str) -> tuple[str, dict[str, str]]:
    """The purl type, and its qualifiers decoded. ``("", {})`` for something that is not a purl."""
    if not purl.startswith("pkg:"):
        return "", {}
    body = purl[len("pkg:") :].split("#", 1)[0]
    head, _, query = body.partition("?")
    purl_type = head.split("/", 1)[0].lower()
    qualifiers: dict[str, str] = {}
    for pair in query.split("&") if query else []:
        key, sep, value = pair.partition("=")
        if sep and key:
            qualifiers[unquote(key)] = unquote(value)
    return purl_type, qualifiers


def _license(component: Mapping[str, Any]) -> str:
    """An SPDX expression from the component's licenses; names that are not SPDX ids are left out."""
    expressions: list[str] = []
    ids: list[str] = []
    for choice in component.get("licenses") or []:
        if not isinstance(choice, dict):
            continue
        if _text(choice.get("expression")):
            expressions.append(_text(choice["expression"]))
        license_ = choice.get("license")
        if isinstance(license_, dict) and _text(license_.get("id")):
            ids.append(_text(license_["id"]))
    if len(expressions) == 1 and not ids:
        return expressions[0]
    parts = [f"({e})" if " " in e else e for e in expressions] + ids
    return " AND ".join(parts)


def _label(entity_type: str, key: Mapping[str, object]) -> str:
    """A batch-local label for a node: the grid's own identity string over its natural key."""
    label = identity_lock_key(entity_type, key)
    if label is None:  # pragma: no cover - every key here is a string, never a hole
        raise SbomParseError(f"{entity_type} has an incomplete natural key {dict(key)!r}")
    return label


def _edge_ref(edge_type: str, from_label: str, to_label: str) -> str:
    return _label(f"edge:{edge_type}", {"from": from_label, "to": to_label})


def _canonical(component: Mapping[str, Any]) -> str:
    return json.dumps(component, sort_keys=True, separators=(",", ":"))


# --- the parser -------------------------------------------------------------------------------


def parse_cyclonedx(data: bytes, *, host_id: str) -> SbomBatch:
    """Turn one CycloneDX 1.4 to 1.7 JSON document into the grid's inventory rows.

    ``data`` is the document's exact bytes (the digest is over them, not over a re-serialisation).
    ``host_id`` is the entity id of the ``host`` the document describes, resolved by the caller.
    Raises ``SbomParseError`` for anything unreadable; never returns an empty batch.
    """
    try:
        host = str(uuid.UUID(str(host_id)))
    except ValueError, AttributeError, TypeError:
        raise SbomParseError(f"host_id {host_id!r} is not an entity id (a UUID)") from None

    document = _load(data)
    spec_version = _check_format(document)
    components = _flatten(document)

    skipped_components: Counter[str] = Counter()
    notes: list[str] = []

    # bom-ref is a handle inside one document: it resolves dependencies and is stored nowhere.
    refs: dict[str, Mapping[str, Any]] = {}
    for component in components:
        bom_ref = component.get("bom-ref")
        if isinstance(bom_ref, str) and bom_ref:
            if bom_ref in refs:
                raise SbomParseError(f"bom-ref {bom_ref!r} names two components, so a dependency on it is ambiguous")
            refs[bom_ref] = component

    packages: dict[tuple[str, str, str], list[Mapping[str, Any]]] = {}
    libraries: dict[tuple[str, str, str], list[Mapping[str, Any]]] = {}
    systems: dict[tuple[str, str, str], list[Mapping[str, Any]]] = {}
    kind_of: dict[int, tuple[str, tuple[str, str, str]]] = {}

    for component in components:
        name, version = _text(component.get("name")), _text(component.get("version"))
        purl = _text(component.get("purl"))
        purl_type, _ = _purl_parts(purl)
        ctype = _text(component.get("type"))
        if not name:
            skipped_components["no name"] += 1
            continue
        if not version:
            skipped_components["no version"] += 1
            continue
        if ctype == "operating-system":
            props, _ = _properties(component)
            key = (props.get("syft:distro:id") or name, props.get("syft:distro:versionID") or version, "")
            systems.setdefault(key, []).append(component)
            kind_of[id(component)] = ("os", key)
        elif purl_type in PACKAGE_PURL_TYPES:
            key = (purl_type, name, version)
            packages.setdefault(key, []).append(component)
            kind_of[id(component)] = ("package", key)
        elif purl_type in LIBRARY_PURL_TYPES or (not purl and ctype in LIBRARY_COMPONENT_TYPES):
            key = (purl_type or "generic", name, version)
            libraries.setdefault(key, []).append(component)
            kind_of[id(component)] = ("library", key)
        elif purl:
            skipped_components[f"unsupported purl type {purl_type or purl!r}"] += 1
        else:
            skipped_components[f"no purl and CycloneDX type {ctype!r} is not software"] += 1

    nodes: dict[str, NodeRow] = {}
    edges: dict[str, EdgeRow] = {}
    purl_conflicts: list[str] = []
    duplicates = 0

    def pick(copies: list[Mapping[str, Any]], key: tuple[str, str, str]) -> Mapping[str, Any]:
        """The one copy a duplicated key keeps: smallest purl, then smallest canonical text."""
        nonlocal duplicates
        if len(copies) == 1:
            return copies[0]
        duplicates += len(copies) - 1
        ordered = sorted(copies, key=lambda c: (_text(c.get("purl")), _canonical(c)))
        purls = sorted({_text(c.get("purl")) for c in copies})
        if len(purls) > 1:
            purl_conflicts.append(f"{'/'.join(key)}: kept {purls[0]!r}, dropped {purls[1:]!r}")
        return ordered[0]

    # packages, and the source package each apk package is built from
    package_labels: dict[tuple[str, str, str], str] = {}
    source_labels: dict[tuple[str, str, str], str] = {}
    for key in sorted(packages):
        component = pick(packages[key], key)
        ecosystem, name, version = key
        props, cpe_values = _properties(component)
        purl = _text(component.get("purl"))
        _, qualifiers = _purl_parts(purl)
        architecture = qualifiers.get("arch", "")
        if architecture and not _ARCHITECTURE.match(architecture):
            notes.append(f"{'/'.join(key)}: arch qualifier {architecture!r} is not one architecture; left empty")
            architecture = ""
        cpe = _text(component.get("cpe"))
        candidates = [c for c in dict.fromkeys(cpe_values) if c != cpe and c.startswith("cpe:2.3:")]
        dropped = [c for c in dict.fromkeys(cpe_values) if c != cpe and not c.startswith("cpe:2.3:")]
        if dropped:
            notes.append(f"{'/'.join(key)}: {len(dropped)} syft:cpe23 value(s) are not CPE 2.3 names; left out")
        label = _label(PACKAGE, {"ecosystem": ecosystem, "name": name, "version": version})
        package_labels[key] = label
        nodes[label] = NodeRow(
            ref=label,
            entity_type=PACKAGE,
            name=name,
            properties={
                "ecosystem": ecosystem,
                "name": name,
                "version": version,
                "architecture": architecture,
                "purl": purl,
                "cpe": cpe,
                "cpe_candidates": candidates,
                "license": _license(component),
                "source_document": "sbom",
            },
        )
        if ecosystem == "apk":
            origin = _text(props.get("syft:metadata:originPackage")) or _text(qualifiers.get("upstream")) or name
            source_key = (ecosystem, origin, version)
            if source_key not in source_labels:
                source_labels[source_key] = _label(
                    SOURCE_PACKAGE, {"ecosystem": ecosystem, "name": origin, "version": version}
                )
                nodes[source_labels[source_key]] = NodeRow(
                    ref=source_labels[source_key],
                    entity_type=SOURCE_PACKAGE,
                    name=origin,
                    properties={"ecosystem": ecosystem, "name": origin, "version": version},
                )
            edge_ref = _edge_ref(DERIVES_FROM_SOURCE_PACKAGE, label, source_labels[source_key])
            edges[edge_ref] = EdgeRow(
                ref=edge_ref, edge_type=DERIVES_FROM_SOURCE_PACKAGE, from_ref=label, to_ref=source_labels[source_key]
            )

    # libraries
    for key in sorted(libraries):
        component = pick(libraries[key], key)
        ecosystem, name, version = key
        props, _ = _properties(component)
        label = _label(LIBRARY, {"ecosystem": ecosystem, "name": name, "version": version})
        source_kind = props.get("tap:source_kind")
        properties: dict[str, Any] = {
            "ecosystem": ecosystem,
            "name": name,
            "version": version,
            "purl": _text(component.get("purl")),
            "cpe": _text(component.get("cpe")),
            "license": _license(component),
            "source_kind": source_kind if source_kind in SOURCE_KINDS else None,
            "source_url": props.get("tap:source", ""),
            "path": props.get("tap:path", ""),
        }
        nodes[label] = NodeRow(ref=label, entity_type=LIBRARY, name=name, properties=properties)

    # operating systems
    system_labels: list[str] = []
    for key in sorted(systems):
        component = pick(systems[key], key)
        os_id, version_id, build_id = key
        props, _ = _properties(component)
        label = _label(OPERATING_SYSTEM, {"os_id": os_id, "version_id": version_id, "build_id": build_id})
        system_labels.append(label)
        display = props.get("syft:distro:prettyName") or _text(component.get("name"))
        nodes[label] = NodeRow(
            ref=label,
            entity_type=OPERATING_SYSTEM,
            name=display,
            properties={"os_id": os_id, "version_id": version_id, "build_id": build_id, "name": display},
        )

    # the document itself
    raw_metadata = document.get("metadata")
    metadata: Mapping[str, Any] = raw_metadata if isinstance(raw_metadata, dict) else {}
    digest = hashlib.sha256(bytes(data)).hexdigest()
    raw_subject = metadata.get("component")
    subject: Mapping[str, Any] = raw_subject if isinstance(raw_subject, dict) else {}
    subject_digest = _text(subject.get("version")) if _IMAGE_DIGEST.match(_text(subject.get("version"))) else ""
    serial = _text(document.get("serialNumber"))
    if serial and not _SERIAL.match(serial):
        notes.append(f"serialNumber {serial!r} is not urn:uuid:...; left empty")
        serial = ""
    revision = document.get("version")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
        revision = 1
    produced = _text(metadata.get("timestamp"))
    if produced:
        try:
            datetime.fromisoformat(produced)
        except ValueError:
            notes.append(f"metadata.timestamp {produced!r} is not an ISO 8601 time; left out")
            produced = ""
    document_label = _label(SBOM_DOCUMENT, {"content_digest": digest})
    nodes[document_label] = NodeRow(
        ref=document_label,
        entity_type=SBOM_DOCUMENT,
        name=f"sbom {digest[:12]} r{revision}",
        properties={
            "content_digest": digest,
            "format": "cyclonedx",
            "spec_version": spec_version,
            "serial_number": serial,
            "revision": revision,
            "subject_digest": subject_digest,
            "produced_at": produced or None,
            "generator": _generator(metadata),
            "component_count": len(components),
        },
    )

    # the host's edges: it installs each package and runs each operating system; the document
    # describes it
    host_label = _label(HOST, {"entity_id": host})
    for label in package_labels.values():
        ref = _edge_ref(INSTALLS_PACKAGE, host_label, label)
        edges[ref] = EdgeRow(ref=ref, edge_type=INSTALLS_PACKAGE, from_entity_id=host, to_ref=label)
    for label in system_labels:
        ref = _edge_ref(RUNS_OPERATING_SYSTEM, host_label, label)
        edges[ref] = EdgeRow(ref=ref, edge_type=RUNS_OPERATING_SYSTEM, from_entity_id=host, to_ref=label)
    ref = _edge_ref(DESCRIBES_HOST, document_label, host_label)
    edges[ref] = EdgeRow(ref=ref, edge_type=DESCRIBES_HOST, from_ref=document_label, to_entity_id=host)

    # dependencies between packages
    skipped_dependencies: Counter[str] = Counter()
    duplicate_dependencies = 0
    listed = 0
    for entry in document.get("dependencies") or []:
        if not isinstance(entry, dict):
            skipped_dependencies["entry is not an object"] += 1
            continue
        depender_ref = entry.get("ref")
        depender = refs.get(depender_ref) if isinstance(depender_ref, str) else None
        targets = entry.get("dependsOn") or []
        if not isinstance(targets, list):
            skipped_dependencies["dependsOn is not a list"] += 1
            continue
        for target_ref in targets:
            listed += 1
            if listed > MAX_DEPENDENCIES:
                raise SbomParseError(f"the document lists more than {MAX_DEPENDENCIES} dependsOn entries, over the cap")
            target = refs.get(target_ref) if isinstance(target_ref, str) else None
            if depender is None:
                skipped_dependencies["the depending ref names no listed component"] += 1
                continue
            if target is None:
                skipped_dependencies["dependsOn names no listed component"] += 1
                continue
            source_kind, source_key = kind_of.get(id(depender), ("", ("", "", "")))
            target_kind, target_key = kind_of.get(id(target), ("", ("", "", "")))
            if source_kind != "package" or target_kind != "package":
                skipped_dependencies["an end is not a package (library, operating system or skipped)"] += 1
                continue
            if source_key == target_key:
                skipped_dependencies["a package depending on itself"] += 1
                continue
            ref = _edge_ref(REQUIRES_PACKAGE, package_labels[source_key], package_labels[target_key])
            if ref in edges:
                duplicate_dependencies += 1
                continue
            edges[ref] = EdgeRow(
                ref=ref,
                edge_type=REQUIRES_PACKAGE,
                from_ref=package_labels[source_key],
                to_ref=package_labels[target_key],
            )

    report = SbomReport(
        component_count=len(components),
        skipped_components=dict(sorted(skipped_components.items())),
        skipped_dependencies=dict(sorted(skipped_dependencies.items())),
        duplicate_components_collapsed=duplicates,
        duplicate_dependencies_collapsed=duplicate_dependencies,
        purl_conflicts=tuple(sorted(purl_conflicts)),
        notes=tuple(sorted(notes)),
    )
    ordered_nodes = tuple(sorted(nodes.values(), key=lambda n: (n.entity_type, n.ref)))
    ordered_edges = tuple(sorted(edges.values(), key=lambda e: (e.edge_type, e.ref)))
    if not any(n.entity_type in (PACKAGE, LIBRARY, OPERATING_SYSTEM) for n in ordered_nodes):
        raise SbomParseError(
            "the document lists components but none is a package, library or operating system: "
            + (", ".join(f"{count} with {why}" for why, count in sorted(skipped_components.items())) or "none readable")
        )
    return SbomBatch(nodes=ordered_nodes, edges=ordered_edges, report=report)


def _generator(metadata: Mapping[str, Any]) -> str:
    """The first tool as ``name@version``; CycloneDX 1.4 lists tools, 1.5+ nests them under components."""
    tools = metadata.get("tools")
    if isinstance(tools, dict):
        tools = tools.get("components")
    if isinstance(tools, list) and tools and isinstance(tools[0], dict):
        name, version = _text(tools[0].get("name")), _text(tools[0].get("version"))
        if name:
            return f"{name}@{version}" if version else name
    return ""
