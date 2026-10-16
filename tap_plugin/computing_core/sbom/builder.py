"""Build a throwaway CycloneDX 1.6 document from inventory the grid holds, purely.

The parser run backwards. It exists so a vulnerability scanner can be handed what the grid says is
deployed: a document carrying exactly the fields scanners match on (the whole purl with its
``arch``, ``distro`` and ``upstream`` qualifiers, ``cpe``, and each ``cpe_candidates`` entry as a
``syft:cpe23`` property), the libraries, and the operating system's distro properties. It writes
nothing to the grid and nothing to disk, reads no clock and invents no identifier, so the same
inputs give the same bytes.

The output is ASCII (non-ASCII characters are JSON escapes), so no input can make the encode fail.

Inputs are plain mappings of the node properties (``ecosystem``, ``name``, ``version``, ``purl``,
``cpe``, ``cpe_candidates``, ``architecture``, ``license``, ...), so this module imports no Django.

Spec: specs/spec-computing-core-v0.md (req-computing-core-sbom-build).
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from typing import Any, Final
from urllib.parse import quote

#: Every scanner tried reads 1.6; Trivy 0.70.0 could not decode 1.7 (tap#1036).
SPEC_VERSION: Final[str] = "1.6"

#: One package or library as a mapping of node properties.
Properties = Mapping[str, Any]
#: A ``(ecosystem, name, version)`` natural key.
PackageKey = tuple[str, str, str]


def _key(properties: Properties) -> PackageKey:
    return (str(properties["ecosystem"]), str(properties["name"]), str(properties["version"]))


def _license(expression: str) -> list[dict[str, str]]:
    return [{"expression": expression}] if expression else []


def _one_per_key(rows: Iterable[Properties]) -> list[Properties]:
    """One row per ``(ecosystem, name, version)``, in key order.

    Two rows with one key are one package on the grid (the key is its identity), so they are one
    component here. Which row is kept does not depend on input order: the smallest by purl, then by
    the rows' own text.
    """
    chosen: dict[PackageKey, Properties] = {}
    for row in rows:
        rank = lambda r: (str(r.get("purl") or ""), json.dumps(r, sort_keys=True, default=str))  # noqa: E731
        if _key(row) not in chosen or rank(row) < rank(chosen[_key(row)]):
            chosen[_key(row)] = row
    return [chosen[key] for key in sorted(chosen)]


def build_cyclonedx(
    packages: Iterable[Properties],
    libraries: Iterable[Properties] = (),
    operating_system: Properties | None = None,
    *,
    requires: Iterable[tuple[PackageKey, PackageKey]] = (),
) -> bytes:
    """Return a CycloneDX 1.6 JSON document for these packages, libraries and operating system.

    ``requires`` pairs of package keys become ``dependencies``; it is keyword-only and optional
    because ``REQUIRES_PACKAGE`` edges are not package properties. Components and dependencies are
    sorted and keys are sorted, so two calls on the same inputs return identical bytes.
    """
    components: list[dict[str, Any]] = []
    ref_of: dict[PackageKey, str] = {}
    used: set[str] = set()

    def bom_ref(properties: Properties, kind: str, purl: str) -> str:
        """The purl where there is one and it is unused, else a deterministic handle."""
        handle = purl if purl and purl not in used else f"computing-core:{kind}:{'/'.join(_key(properties))}"
        used.add(handle)
        return handle

    for properties in _one_per_key(packages):
        ecosystem, name, version = _key(properties)
        # A package the grid holds with no purl still needs one, or a reader (this parser, a
        # scanner) would not know its package manager: the minimal purl is written for the
        # document only, and the grid's own row is untouched.
        purl = str(
            properties.get("purl")
            or f"pkg:{ecosystem}/{quote(name, safe='', errors='replace')}@{quote(version, safe='', errors='replace')}"
        )
        ref = bom_ref(properties, "package", purl)
        ref_of[_key(properties)] = ref
        component: dict[str, Any] = {
            "type": "library",
            "bom-ref": ref,
            "name": name,
            "version": version,
            "purl": purl,
        }
        if properties.get("cpe"):
            component["cpe"] = properties["cpe"]
        licenses = _license(str(properties.get("license") or ""))
        if licenses:
            component["licenses"] = licenses
        candidates = [{"name": "syft:cpe23", "value": c} for c in properties.get("cpe_candidates") or []]
        if candidates:
            component["properties"] = candidates
        components.append(component)

    for properties in _one_per_key(libraries):
        ecosystem, name, version = _key(properties)
        ref = bom_ref(properties, "library", str(properties.get("purl") or ""))
        component = {"type": "library", "bom-ref": ref, "name": name, "version": version}
        if properties.get("purl"):
            component["purl"] = properties["purl"]
        if properties.get("cpe"):
            component["cpe"] = properties["cpe"]
        licenses = _license(str(properties.get("license") or ""))
        if licenses:
            component["licenses"] = licenses
        extra = [
            {"name": prop, "value": str(properties[field])}
            for prop, field in (("tap:source_kind", "source_kind"), ("tap:source", "source_url"), ("tap:path", "path"))
            if properties.get(field)
        ]
        if extra:
            component["properties"] = extra
        components.append(component)

    if operating_system:
        os_id, version_id = str(operating_system["os_id"]), str(operating_system.get("version_id") or "")
        distro = [{"name": "syft:distro:id", "value": os_id}, {"name": "syft:distro:versionID", "value": version_id}]
        if operating_system.get("name"):
            distro.append({"name": "syft:distro:prettyName", "value": str(operating_system["name"])})
        components.append(
            {
                "type": "operating-system",
                "bom-ref": f"computing-core:os:{os_id}/{version_id}",
                "name": os_id,
                "version": version_id,
                "properties": sorted(distro, key=lambda p: p["name"]),
            }
        )

    depends: dict[str, set[str]] = {}
    for source, target in requires:
        if source in ref_of and target in ref_of and source != target:
            depends.setdefault(ref_of[source], set()).add(ref_of[target])
    dependencies = [{"ref": ref, "dependsOn": sorted(targets)} for ref, targets in sorted(depends.items())]

    document: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "version": 1,
        "components": components,
        "dependencies": dependencies,
    }
    return json.dumps(document, sort_keys=True, indent=1, ensure_ascii=True).encode("utf-8")
