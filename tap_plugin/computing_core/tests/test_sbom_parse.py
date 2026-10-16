"""Tests for `parse_cyclonedx` (req-computing-core-sbom-parse and the package/dependency ACIDs it feeds).

The corpus is the attested tap-web SBOM, unmodified (tests/corpus/): image `sha256:a9149a88...`,
CycloneDX 1.7, Syft 1.51.0, 192 components. Every number asserted here can be re-read from it.
No test needs a database: the parser is pure.
"""

import hashlib
import json
import multiprocessing
import random
import uuid
from collections import Counter
from pathlib import Path

import jsonschema
import pytest
from tap_plugin.computing_core.sbom import SbomBatch, SbomParseError, parse_cyclonedx
from tap_plugin.computing_core.sbom import parser as parser_module
from tap_plugin.computing_core.tests import _django_free_probe as probe

from tap_grid.registry import get_model_class

CORPUS = Path(__file__).resolve().parent / "corpus" / "tap-web-latest-arm64.cdx.json"
HOST = str(uuid.UUID("01a13c38-4f5e-735c-9cf2-1f159f4282b6"))

PACKAGE = "computing_core__package"
LIBRARY = "computing_core__library"
SOURCE = "computing_core__source_package"
OS = "computing_core__operating_system"
DOCUMENT = "computing_core__sbom_document"


@pytest.fixture(scope="module")
def corpus_bytes() -> bytes:
    return CORPUS.read_bytes()


@pytest.fixture(scope="module")
def corpus(corpus_bytes: bytes) -> dict:
    return json.loads(corpus_bytes)


@pytest.fixture(scope="module")
def batch(corpus_bytes: bytes) -> SbomBatch:
    return parse_cyclonedx(corpus_bytes, host_id=HOST)


def _doc(components: list[dict], dependencies: list[dict] | None = None, **top) -> bytes:
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": components,
        "dependencies": dependencies or [],
        **top,
    }
    return json.dumps(document).encode()


def _lib(name: str, version: str = "1", ref: str | None = None, purl: str | None = None, **extra) -> dict:
    component = {
        "type": "library",
        "bom-ref": ref or name,
        "name": name,
        "version": version,
        "purl": purl if purl is not None else f"pkg:apk/wolfi/{name}@{version}",
        **extra,
    }
    return {k: v for k, v in component.items() if v is not None}


def _by_name(batch: SbomBatch, entity_type: str) -> dict[str, list]:
    found: dict[str, list] = {}
    for row in batch.nodes_of(entity_type):
        found.setdefault(row.properties["name"], []).append(row)
    return found


def _ends(batch: SbomBatch, edge_type: str) -> set[tuple[str, str]]:
    return {(e.from_ref or "", e.to_ref or "") for e in batch.edges_of(edge_type)}


def _spawned(function, *args):
    """Run `function` in a fresh interpreter, so one process's imports cannot leak into the probe."""
    with multiprocessing.get_context("spawn").Pool(1) as pool:
        return pool.apply(function, args)


class TestPureAndDjangoFree:
    """req-computing-core-sbom-parse-1."""

    def test_the_sbom_package_imports_and_parses_with_django_blocked_and_nothing_opened(self):
        nodes, edges, django_modules = _spawned(probe.parse_with_django_blocked, str(CORPUS), HOST)
        assert nodes > 100
        assert edges > 100
        assert django_modules == []

    def test_the_block_is_real(self):
        """The guard above would pass vacuously if the blocker never fired; prove Django IS refused."""
        assert _spawned(probe.django_is_refused) is True


class TestDeterministic:
    """req-computing-core-sbom-parse-2."""

    def test_the_same_bytes_twice_are_the_same_batch(self, corpus_bytes: bytes, batch: SbomBatch):
        assert parse_cyclonedx(corpus_bytes, host_id=HOST) == batch

    def test_reordered_components_and_dependencies_are_the_same_batch(self, corpus: dict, batch: SbomBatch):
        """Identical but for the document row: its digest is over bytes, and the bytes changed."""
        shuffled = json.loads(json.dumps(corpus))
        rng = random.Random(20261015)
        rng.shuffle(shuffled["components"])
        rng.shuffle(shuffled["dependencies"])
        for entry in shuffled["dependencies"]:
            rng.shuffle(entry["dependsOn"])
        other = parse_cyclonedx(json.dumps(shuffled).encode(), host_id=HOST)

        def without_document(b: SbomBatch):
            nodes = tuple(n for n in b.nodes if n.entity_type != DOCUMENT)
            edges = tuple(e for e in b.edges if e.edge_type != "DESCRIBES_HOST__computing_core")
            return nodes, edges, b.report

        assert without_document(other) == without_document(batch)
        assert (
            other.nodes_of(DOCUMENT)[0].properties["content_digest"]
            != batch.nodes_of(DOCUMENT)[0].properties["content_digest"]
        )

    def test_a_duplicate_with_different_purls_keeps_the_smallest_whatever_the_order(self):
        a = _lib("zlib", purl="pkg:apk/wolfi/zlib@1?arch=x86_64")
        b = _lib("zlib", ref="zlib-b", purl="pkg:apk/wolfi/zlib@1?arch=aarch64")
        forward = parse_cyclonedx(_doc([a, b]), host_id=HOST)
        backward = parse_cyclonedx(_doc([b, a]), host_id=HOST)
        assert forward.nodes_of(PACKAGE) == backward.nodes_of(PACKAGE)
        assert forward.report == backward.report
        assert forward.nodes_of(PACKAGE)[0].properties["purl"] == "pkg:apk/wolfi/zlib@1?arch=aarch64"
        assert forward.report.duplicate_components_collapsed == 1
        assert "kept 'pkg:apk/wolfi/zlib@1?arch=aarch64'" in forward.report.purl_conflicts[0]


class TestTheRealDocument:
    """req-computing-core-sbom-parse-3."""

    def test_package_counts_per_ecosystem(self, batch: SbomBatch):
        by_ecosystem = Counter(n.properties["ecosystem"] for n in batch.nodes_of(PACKAGE))
        assert by_ecosystem == {"apk": 102, "pypi": 71, "npm": 7}

    def test_the_three_libraries(self, batch: SbomBatch):
        assert sorted(n.properties["name"] for n in batch.nodes_of(LIBRARY)) == ["openssl-fips-provider", "uv", "uvx"]

    def test_the_operating_system(self, batch: SbomBatch):
        (wolfi,) = batch.nodes_of(OS)
        assert (wolfi.properties["os_id"], wolfi.properties["version_id"], wolfi.properties["build_id"]) == (
            "wolfi",
            "20230201",
            "",
        )

    def test_source_packages_are_72_pairs_of_70_origin_names(self, batch: SbomBatch):
        sources = batch.nodes_of(SOURCE)
        assert len(sources) == 72
        assert len({n.properties["name"] for n in sources}) == 70

    def test_one_document_and_450_requires_package_edges_and_no_unresolved_reference(self, batch: SbomBatch):
        assert len(batch.nodes_of(DOCUMENT)) == 1
        assert len(batch.edges_of("REQUIRES_PACKAGE__computing_core")) == 450
        assert batch.report.skipped_dependencies == {}
        assert batch.report.skipped_components == {}

    def test_the_450_are_the_457_listed_less_the_duplicated_npm_paths(self, corpus: dict, batch: SbomBatch):
        listed = sum(len(d.get("dependsOn", [])) for d in corpus["dependencies"])
        assert listed == 457
        assert batch.report.duplicate_dependencies_collapsed == 7
        assert batch.report.duplicate_components_collapsed == 8  # 15 npm components, 7 packages
        assert batch.report.component_count == 192

    def test_the_host_installs_every_package_and_runs_the_os_and_the_document_describes_it(self, batch: SbomBatch):
        installs = batch.edges_of("INSTALLS_PACKAGE__computing_core")
        assert len(installs) == 180
        assert {e.from_entity_id for e in installs} == {HOST}
        (runs,) = batch.edges_of("RUNS_OPERATING_SYSTEM__computing_core")
        assert runs.from_entity_id == HOST
        (describes,) = batch.edges_of("DESCRIBES_HOST__computing_core")
        assert describes.to_entity_id == HOST

    def test_the_document_row_describes_the_document(self, batch: SbomBatch, corpus_bytes: bytes):
        (row,) = batch.nodes_of(DOCUMENT)
        assert row.properties == {
            "content_digest": hashlib.sha256(corpus_bytes).hexdigest(),
            "format": "cyclonedx",
            "spec_version": "1.7",
            "serial_number": "urn:uuid:90f083a0-a7b6-4183-a41d-ad1bb111feeb",
            "revision": 1,
            "subject_digest": "sha256:a9149a88a6239fc7a5351d9854fbff42448d2ed28cc71951a4c2aa2f4aca7750",
            "produced_at": "2026-10-15T15:02:05Z",
            "generator": "syft@1.51.0",
            "component_count": 192,
        }

    def test_the_corpus_is_the_attested_document(self, corpus_bytes: bytes):
        assert len(corpus_bytes) == 628_027
        assert hashlib.sha256(corpus_bytes).hexdigest().startswith("734809b9")

    def test_the_libraries_keep_how_the_document_says_they_were_built(self, batch: SbomBatch):
        libs = _by_name(batch, LIBRARY)
        provider = libs["openssl-fips-provider"][0].properties
        assert provider["source_kind"] == "self-built"
        assert provider["path"] == "/usr/lib/ossl-modules/fips.so"
        assert libs["uv"][0].properties["source_kind"] == "copied-image"
        assert libs["uv"][0].properties["ecosystem"] == "github"
        assert provider["ecosystem"] == "generic"


class TestSourcePackagesAreDrawn:
    """req-computing-core-sbom-parse-4."""

    def _source_of(self, batch: SbomBatch, package_name: str, version: str) -> tuple:
        sources = {n.ref: n.properties for n in batch.nodes_of(SOURCE)}
        packages = {
            n.ref: n.properties
            for n in batch.nodes_of(PACKAGE)
            if n.properties["name"] == package_name and n.properties["version"] == version
        }
        (ref,) = packages
        (target,) = [t for f, t in _ends(batch, "DERIVES_FROM_SOURCE_PACKAGE__computing_core") if f == ref]
        return target, (sources[target]["name"], sources[target]["version"])

    def test_every_apk_package_draws_the_edge_and_no_other_ecosystem_does(self, batch: SbomBatch):
        apk = {n.ref for n in batch.nodes_of(PACKAGE) if n.properties["ecosystem"] == "apk"}
        assert {f for f, _ in _ends(batch, "DERIVES_FROM_SOURCE_PACKAGE__computing_core")} == apk
        assert len(batch.edges_of("DERIVES_FROM_SOURCE_PACKAGE__computing_core")) == 102

    def test_libssl3_and_libcrypto3_share_openssl_3_6_4_and_not_the_openssl_package(self, batch: SbomBatch):
        ssl, ssl_key = self._source_of(batch, "libssl3", "3.6.4-r8")
        crypto, crypto_key = self._source_of(batch, "libcrypto3", "3.6.4-r8")
        openssl, openssl_key = self._source_of(batch, "openssl", "3.6.5-r2")
        assert ssl == crypto
        assert ssl_key == ("openssl", "3.6.4-r8")
        assert openssl_key == ("openssl", "3.6.5-r2")
        assert openssl != ssl

    def test_the_two_origins_whose_members_do_not_share_a_version_are_two_nodes_each(self, batch: SbomBatch):
        """The corpus contradicts 'every member of an origin shares one version' for exactly these two."""
        versions: dict[str, set[str]] = {}
        for node in batch.nodes_of(SOURCE):
            versions.setdefault(node.properties["name"], set()).add(node.properties["version"])
        split = {name: v for name, v in versions.items() if len(v) > 1}
        assert split == {"openssl": {"3.6.4-r8", "3.6.5-r2"}, "postgresql-18": {"18.6-r4", "18.6-r5"}}

    def test_a_package_with_no_stated_origin_is_its_own_origin(self):
        batch = parse_cyclonedx(_doc([_lib("busybox", "1.37")]), host_id=HOST)
        (source,) = batch.nodes_of(SOURCE)
        assert (source.properties["name"], source.properties["version"]) == ("busybox", "1.37")
        assert len(batch.edges_of("DERIVES_FROM_SOURCE_PACKAGE__computing_core")) == 1

    def test_the_origin_comes_from_the_property_then_the_purl_upstream_qualifier(self):
        by_property = _lib(
            "libssl3",
            "3",
            purl="pkg:apk/wolfi/libssl3@3?arch=x86_64",
            properties=[{"name": "syft:metadata:originPackage", "value": "openssl"}],
        )
        by_purl = _lib("libcrypto3", "3", purl="pkg:apk/wolfi/libcrypto3@3?arch=x86_64&upstream=openssl")
        batch = parse_cyclonedx(_doc([by_property, by_purl]), host_id=HOST)
        assert [n.properties["name"] for n in batch.nodes_of(SOURCE)] == ["openssl"]


class TestMatchingFieldsSurvive:
    """req-computing-core-sbom-parse-5 and req-computing-core-package-6."""

    def test_libssl3_keeps_its_purl_cpe_and_three_candidates(self, batch: SbomBatch):
        (libssl3,) = _by_name(batch, PACKAGE)["libssl3"]
        props = libssl3.properties
        assert props["purl"] == ("pkg:apk/wolfi/libssl3@3.6.4-r8?arch=aarch64&distro=wolfi-20230201&upstream=openssl")
        assert props["cpe"] == "cpe:2.3:a:libssl3:libssl3:3.6.4-r8:*:*:*:*:*:*:*"
        assert props["cpe_candidates"] == [
            "cpe:2.3:a:libssl3:libssl:3.6.4-r8:*:*:*:*:*:*:*",
            "cpe:2.3:a:libssl:libssl3:3.6.4-r8:*:*:*:*:*:*:*",
            "cpe:2.3:a:libssl:libssl:3.6.4-r8:*:*:*:*:*:*:*",
        ]
        assert props["architecture"] == "aarch64"
        assert props["license"] == "Apache-2.0"
        assert props["source_document"] == "sbom"

    def test_the_fips_provider_keeps_its_cpe(self, batch: SbomBatch):
        (provider,) = _by_name(batch, LIBRARY)["openssl-fips-provider"]
        assert provider.properties["cpe"] == "cpe:2.3:a:openssl:openssl:3.5.8:*:*:*:*:*:*:*"
        assert provider.properties["purl"].startswith("pkg:generic/openssl-fips-provider@3.5.8?download_url=")

    def test_purl_qualifiers_survive(self, corpus: dict, batch: SbomBatch):
        """package-6: every apk purl is exactly the document's, qualifiers and all."""
        document_purls = {c["purl"] for c in corpus["components"] if c.get("purl", "").startswith("pkg:apk/")}
        stored = {n.properties["purl"] for n in batch.nodes_of(PACKAGE) if n.properties["ecosystem"] == "apk"}
        assert stored == document_purls
        assert len(stored) == 102
        assert sum("upstream=" in p for p in stored) == 54
        assert all("arch=" in p and "distro=" in p for p in stored)

    def test_no_candidate_repeats_the_cpe_and_every_one_is_cpe23(self, batch: SbomBatch):
        for node in batch.nodes_of(PACKAGE):
            props = node.properties
            assert props["cpe"] not in props["cpe_candidates"], props["name"]
            assert len(set(props["cpe_candidates"])) == len(props["cpe_candidates"])
            assert all(c.startswith("cpe:2.3:") for c in props["cpe_candidates"])

    def test_every_emitted_property_is_a_model_field_and_passes_the_models_own_schema(self, batch: SbomBatch):
        """Derived from the models, so a rename, a new constraint or a changed limit fails here."""
        for node in batch.nodes:
            model = get_model_class(node.entity_type)
            fields = {f.name for f in model._meta.concrete_fields}
            assert set(node.properties) <= fields, node.entity_type
            for name, value in node.properties.items():
                jsonschema.validate(value, model.FIELD_CRUD_SCHEMA[name])
            assert node.name == node.properties.get("name", node.name)


class TestOneArchitectureNeverAJoin:
    """req-computing-core-package-8 (the writer half)."""

    def test_the_architecture_is_the_purl_arch_and_always_one_token(self, batch: SbomBatch):
        arches = Counter(
            n.properties["architecture"] for n in batch.nodes_of(PACKAGE) if n.properties["ecosystem"] == "apk"
        )
        assert arches == {"aarch64": 102}

    def test_a_joined_arch_qualifier_is_left_empty_and_reported(self):
        joined = _lib("zlib", purl="pkg:apk/wolfi/zlib@1?arch=aarch64%2Cx86_64")
        batch = parse_cyclonedx(_doc([joined]), host_id=HOST)
        assert batch.nodes_of(PACKAGE)[0].properties["architecture"] == ""
        assert any("is not one architecture" in note for note in batch.report.notes)


CYCLONEDX = {"bomFormat": "CycloneDX", "specVersion": "1.6"}


def _body(**extra) -> bytes:
    return json.dumps({**CYCLONEDX, **extra}).encode()


#: (body, a fragment only that case's message contains). The messages must also differ from each other.
UNREADABLE = {
    "empty": (b"", "the document is empty"),
    "not json": (b"not json at all", "not JSON: Expecting value"),
    "undecodable": (b'{"a": "\xff"}', "codec can't decode byte 0xff"),
    "top level is a list": (b"[1, 2, 3]", "top level is list"),
    "no bomFormat": (b'{"hello": "world"}', "bomFormat is None"),
    "wrong bomFormat": (b'{"bomFormat": "SPDX", "specVersion": "1.6"}', "bomFormat is 'SPDX'"),
    "no components": (_body(), "lists no components array"),
    "empty components": (_body(components=[]), "an empty inventory is refused"),
    "a component not an object": (_body(components=[1]), "a component is not an object"),
    "NaN": (b'{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [], "x": NaN}', "contains NaN"),
    "repeated key": (b'{"bomFormat": "CycloneDX", "bomFormat": "CycloneDX"}', "appears twice"),
    "integer literal over the digit limit": (
        b'{"bomFormat": "CycloneDX", "x": ' + b"1" * 5000 + b"}",
        "Exceeds the limit",
    ),
    "lone surrogate": (_body(components=[{"name": "\ud800"}]), "not valid Unicode"),
}


class TestUnreadableIsRefusedNotEmpty:
    """req-computing-core-sbom-parse-6."""

    @pytest.mark.parametrize("case", sorted(UNREADABLE))
    def test_each_is_refused_with_its_own_reason(self, case: str):
        body, fragment = UNREADABLE[case]
        with pytest.raises(SbomParseError) as raised:
            parse_cyclonedx(body, host_id=HOST)
        assert fragment in str(raised.value)

    def test_no_two_cases_share_a_message(self):
        messages = []
        for body, _ in UNREADABLE.values():
            with pytest.raises(SbomParseError) as raised:
                parse_cyclonedx(body, host_id=HOST)
            messages.append(str(raised.value))
        assert len(set(messages)) == len(UNREADABLE)

    def test_a_components_value_that_is_not_a_list_is_refused_like_a_missing_one(self):
        with pytest.raises(SbomParseError, match="lists no components array"):
            parse_cyclonedx(_body(components=5), host_id=HOST)

    def test_a_lone_surrogate_in_a_key_is_refused_too(self):
        with pytest.raises(SbomParseError, match="not valid Unicode"):
            parse_cyclonedx(_body(components=[{"\ud800": 1}]), host_id=HOST)

    def test_only_sbom_parse_error_ever_escapes(self):
        """Whatever the shape, the exception type is the parser's own."""
        for body, _ in UNREADABLE.values():
            with pytest.raises(SbomParseError):
                parse_cyclonedx(body, host_id=HOST)

    def test_the_real_size_cap_is_8_mib_and_a_body_one_byte_over_is_refused_unparsed(self):
        assert parser_module.MAX_BYTES == 8 * 1024 * 1024
        with pytest.raises(SbomParseError, match=r"8388608-byte size cap"):
            parse_cyclonedx(b" " * (parser_module.MAX_BYTES + 1), host_id=HOST)

    def test_a_body_over_the_size_cap_is_refused_naming_the_cap(self, monkeypatch, corpus_bytes: bytes):
        monkeypatch.setattr(parser_module, "MAX_BYTES", 1000)
        with pytest.raises(SbomParseError, match="1000-byte size cap"):
            parse_cyclonedx(corpus_bytes, host_id=HOST)

    def test_a_body_nested_past_the_depth_cap_is_refused_naming_the_cap(self):
        deep = b"[" * 200 + b"]" * 200
        with pytest.raises(SbomParseError, match="64-level depth cap"):
            parse_cyclonedx(deep, host_id=HOST)

    def test_a_body_nested_past_the_interpreter_is_refused_not_crashed(self):
        deep = b"[" * 200_000 + b"]" * 200_000
        with pytest.raises(SbomParseError, match="depth cap"):
            parse_cyclonedx(deep, host_id=HOST)

    def test_more_components_than_the_cap_is_refused_naming_the_cap(self, monkeypatch):
        monkeypatch.setattr(parser_module, "MAX_COMPONENTS", 2)
        with pytest.raises(SbomParseError, match="component cap"):
            parse_cyclonedx(_doc([_lib("a"), _lib("b"), _lib("c")]), host_id=HOST)

    def test_a_document_with_components_but_none_readable_is_refused(self):
        nameless = {"type": "library", "version": "1", "purl": "pkg:apk/wolfi/x@1"}
        with pytest.raises(SbomParseError, match="none is a package"):
            parse_cyclonedx(_doc([nameless]), host_id=HOST)

    def test_two_components_sharing_a_bom_ref_are_refused(self):
        with pytest.raises(SbomParseError, match="names two components"):
            parse_cyclonedx(_doc([_lib("a", ref="same"), _lib("b", ref="same")]), host_id=HOST)

    @pytest.mark.parametrize("host_id", ["", "not-a-uuid", None, 5])
    def test_a_host_id_that_is_not_an_entity_id_is_refused(self, host_id):
        with pytest.raises(SbomParseError, match="host_id"):
            parse_cyclonedx(_doc([_lib("a")]), host_id=host_id)

    def test_a_non_bytes_body_is_refused(self):
        with pytest.raises(SbomParseError, match="must be bytes"):
            parse_cyclonedx("{}", host_id=HOST)  # type: ignore[arg-type]


class TestCycloneDxOneFourToOneSeven:
    """req-computing-core-sbom-parse-7."""

    @pytest.mark.parametrize("version", ["1.4", "1.5", "1.6", "1.7"])
    def test_these_parse(self, version: str):
        tools = (
            [{"vendor": "anchore", "name": "syft", "version": "1.0"}]
            if version == "1.4"
            else {"components": [{"type": "application", "name": "syft", "version": "1.0"}]}
        )
        batch = parse_cyclonedx(_doc([_lib("zlib")], specVersion=version, metadata={"tools": tools}), host_id=HOST)
        assert batch.nodes_of(DOCUMENT)[0].properties["spec_version"] == version
        assert batch.nodes_of(DOCUMENT)[0].properties["generator"] == "syft@1.0"

    @pytest.mark.parametrize("version", ["1.0", "1.1", "1.2", "1.3", "1.8", "2.0", "", None])
    def test_these_are_refused_naming_the_version(self, version):
        with pytest.raises(SbomParseError, match="specVersion"):
            parse_cyclonedx(_doc([_lib("zlib")], specVersion=version), host_id=HOST)

    def test_spdx_is_refused_naming_the_format(self):
        spdx = json.dumps({"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "packages": []}).encode()
        with pytest.raises(SbomParseError, match="SPDX"):
            parse_cyclonedx(spdx, host_id=HOST)


class TestSkipsAreCounted:
    """req-computing-core-sbom-parse-8 and req-computing-core-package-dependency-3."""

    def test_a_component_with_no_name_or_no_version_is_counted_with_its_reason(self):
        components = [
            _lib("ok"),
            {"type": "library", "bom-ref": "n", "version": "1", "purl": "pkg:apk/wolfi/n@1"},
            {"type": "library", "bom-ref": "v", "name": "v", "purl": "pkg:apk/wolfi/v"},
        ]
        batch = parse_cyclonedx(_doc(components), host_id=HOST)
        assert batch.report.skipped_components == {"no name": 1, "no version": 1}
        assert [n.properties["name"] for n in batch.nodes_of(PACKAGE)] == ["ok"]

    def test_an_unsupported_purl_type_is_counted_not_dropped_silently(self):
        batch = parse_cyclonedx(_doc([_lib("ok"), _lib("img", purl="pkg:oci/img@1")]), host_id=HOST)
        assert batch.report.skipped_components == {"unsupported purl type 'oci'": 1}

    def test_dependencies_that_name_a_library_an_unlisted_component_or_nothing_are_counted(self):
        components = [_lib("a"), _lib("b"), _lib("lib", purl="pkg:generic/lib@1")]
        dependencies = [{"ref": "a", "dependsOn": ["b", "lib", "ghost"]}, {"ref": "nobody", "dependsOn": ["a"]}]
        batch = parse_cyclonedx(_doc(components, dependencies), host_id=HOST)
        assert len(batch.edges_of("REQUIRES_PACKAGE__computing_core")) == 1
        assert batch.report.skipped_dependencies == {
            "an end is not a package (library, operating system or skipped)": 1,
            "dependsOn names no listed component": 1,
            "the depending ref names no listed component": 1,
        }

    def test_a_component_depending_on_itself_yields_no_edge(self):
        batch = parse_cyclonedx(_doc([_lib("a"), _lib("b")], [{"ref": "a", "dependsOn": ["a", "b"]}]), host_id=HOST)
        assert len(batch.edges_of("REQUIRES_PACKAGE__computing_core")) == 1
        assert batch.report.skipped_dependencies == {"a package depending on itself": 1}

    def test_two_listings_of_one_package_are_one_node_so_a_link_between_them_is_a_self_edge(self):
        twin = _lib("a", ref="a-2")
        batch = parse_cyclonedx(_doc([_lib("a"), twin], [{"ref": "a", "dependsOn": ["a-2"]}]), host_id=HOST)
        assert batch.edges_of("REQUIRES_PACKAGE__computing_core") == ()
        assert batch.report.skipped_dependencies == {"a package depending on itself": 1}


class TestDigestOverTheExactBytes:
    """req-computing-core-sbom-parse-9."""

    def test_the_digest_is_sha256_of_the_bytes_passed_in(self):
        data = _doc([_lib("a")])
        (row,) = parse_cyclonedx(data, host_id=HOST).nodes_of(DOCUMENT)
        assert row.properties["content_digest"] == hashlib.sha256(data).hexdigest()

    def test_a_reserialisation_of_the_same_content_has_another_digest(self):
        data = _doc([_lib("a")])
        reserialised = json.dumps(json.loads(data), indent=4).encode()
        a = parse_cyclonedx(data, host_id=HOST).nodes_of(DOCUMENT)[0]
        b = parse_cyclonedx(reserialised, host_id=HOST).nodes_of(DOCUMENT)[0]
        assert a.properties["content_digest"] != b.properties["content_digest"]
        assert b.properties["content_digest"] == hashlib.sha256(reserialised).hexdigest()


def _comp(name="p", version="1", **extra) -> dict:
    return _lib(name, version, **extra)


class TestHostileShapesNeverRaiseAnythingElse:
    """A field of the wrong shape is ignored and noted; it never raises a TypeError or AttributeError."""

    @pytest.mark.parametrize("value", [5, "text", {"a": 1}, True, 1.5])
    def test_properties_that_is_not_a_list(self, value):
        batch = parse_cyclonedx(_doc([_comp(properties=value)]), host_id=HOST)
        assert any("properties is not a list" in n for n in batch.report.notes)
        assert len(batch.nodes_of(PACKAGE)) == 1

    @pytest.mark.parametrize("value", [5, "MIT", {"license": {"id": "MIT"}}])
    def test_licenses_that_is_not_a_list(self, value):
        batch = parse_cyclonedx(_doc([_comp(licenses=value)]), host_id=HOST)
        assert any("licenses is not a list" in n for n in batch.report.notes)
        assert batch.nodes_of(PACKAGE)[0].properties["license"] == ""

    @pytest.mark.parametrize("value", [5, "x", {"ref": "a"}])
    def test_top_level_dependencies_that_is_not_a_list(self, value):
        batch = parse_cyclonedx(_doc([_comp()], dependencies=value), host_id=HOST)
        assert batch.report.skipped_dependencies == {"dependencies is not a list": 1}

    @pytest.mark.parametrize("value", [5, "a", {"a": 1}])
    def test_depends_on_that_is_not_a_list(self, value):
        batch = parse_cyclonedx(_doc([_comp()], [{"ref": "p", "dependsOn": value}]), host_id=HOST)
        assert batch.report.skipped_dependencies == {"dependsOn is not a list": 1}

    def test_unhashable_and_non_string_refs(self):
        components = [_comp("a", ref="a"), _comp("b", ref="b")]
        dependencies = [
            {"ref": {"x": 1}, "dependsOn": ["a"]},
            {"ref": ["a"], "dependsOn": ["b"]},
            {"ref": "a", "dependsOn": [{"x": 1}, ["b"], 7, None, "b"]},
            "not an object",
            5,
        ]
        batch = parse_cyclonedx(_doc(components, dependencies), host_id=HOST)
        assert len(batch.edges_of("REQUIRES_PACKAGE__computing_core")) == 1
        assert batch.report.skipped_dependencies["entry is not an object"] == 2

    @pytest.mark.parametrize("field", ["name", "version", "purl", "cpe", "type", "bom-ref"])
    @pytest.mark.parametrize("value", [5, ["x"], {"a": 1}, None, True])
    def test_scalar_fields_of_the_wrong_type_are_read_as_absent(self, field, value):
        component = _comp(ref="ok")
        component[field] = value
        try:
            batch = parse_cyclonedx(_doc([component, _comp("other", ref="other")]), host_id=HOST)
        except SbomParseError:
            return  # a refusal is allowed; any other exception type is the failure
        assert batch.nodes_of(PACKAGE)

    def test_metadata_and_tools_of_the_wrong_shape(self):
        for metadata in (5, [], {"tools": 5}, {"tools": [5]}, {"tools": {"components": 5}}, {"component": 5}):
            batch = parse_cyclonedx(_doc([_comp()], metadata=metadata), host_id=HOST)
            assert batch.nodes_of(DOCUMENT)[0].properties["generator"] == ""

    def test_an_integer_literal_over_the_interpreter_digit_limit_is_a_parse_error(self):
        with pytest.raises(SbomParseError, match="Exceeds the limit"):
            parse_cyclonedx(b'{"a": ' + b"9" * 5000 + b"}", host_id=HOST)


class TestValuesNeverExceedTheModelColumns:
    """A value the model would refuse is skipped or left empty with a note, never emitted."""

    @pytest.mark.parametrize(
        ("component", "reason"),
        [
            (_comp("n" * 256), "name longer than 255 characters"),
            (_comp("n", "v" * 129), "version longer than 128 characters"),
            (_comp("n", purl="pkg:apk/wolfi/n@1?x=" + "q" * 1010), "purl longer than 1024 characters"),
            (_comp("n", purl="pkg:" + "a" * 33 + "/n@1"), "purl type longer than 32 characters"),
        ],
    )
    def test_a_component_with_an_over_long_key_field_is_skipped_and_counted(self, component, reason):
        batch = parse_cyclonedx(_doc([_comp("ok"), component]), host_id=HOST)
        assert batch.report.skipped_components == {reason: 1}
        assert [n.properties["name"] for n in batch.nodes_of(PACKAGE)] == ["ok"]

    @pytest.mark.parametrize(
        ("extra", "field", "note"),
        [
            ({"cpe": "cpe:2.3:" + "c" * 510}, "cpe", "cpe is longer than 512"),
            ({"licenses": [{"expression": "L" * 513}]}, "license", "license is longer than 512"),
        ],
    )
    def test_an_over_long_optional_field_is_left_empty_and_noted(self, extra, field, note):
        batch = parse_cyclonedx(_doc([_comp(**extra)]), host_id=HOST)
        assert batch.nodes_of(PACKAGE)[0].properties[field] == ""
        assert any(note in n for n in batch.report.notes)

    def test_an_over_long_architecture_is_left_empty_and_noted(self):
        batch = parse_cyclonedx(_doc([_comp(purl="pkg:apk/wolfi/p@1?arch=" + "a" * 33)]), host_id=HOST)
        assert batch.nodes_of(PACKAGE)[0].properties["architecture"] == ""
        assert any("is not one architecture" in n for n in batch.report.notes)

    def test_document_fields_over_their_limits_are_left_out_and_noted(self):
        metadata = {
            "timestamp": "20261015",
            "tools": [{"name": "t" * 300, "version": "1"}],
            "component": {"version": "sha256:" + "a" * 200},
        }
        batch = parse_cyclonedx(
            _doc([_comp()], metadata=metadata, version=2**31, serialNumber="urn:uuid:nope"), host_id=HOST
        )
        props = batch.nodes_of(DOCUMENT)[0].properties
        assert (props["produced_at"], props["generator"], props["subject_digest"]) == (None, "", "")
        assert (props["revision"], props["serial_number"]) == (1, "")
        notes = " | ".join(batch.report.notes)
        for fragment in ("not an RFC 3339", "generator is longer", "document version", "serialNumber"):
            assert fragment in notes

    def test_an_over_long_operating_system_id_is_skipped_and_counted(self):
        system = {"type": "operating-system", "name": "o" * 65, "version": "1"}
        batch = parse_cyclonedx(_doc([_comp(), system]), host_id=HOST)
        assert sum(batch.report.skipped_components.values()) == 1
        assert batch.nodes_of(OS) == ()

    def test_the_widest_values_that_fit_are_kept(self):
        component = _comp("n" * 255, "v" * 128, purl="pkg:apk/wolfi/x@1?arch=" + "a" * 32)
        batch = parse_cyclonedx(_doc([component]), host_id=HOST)
        props = batch.nodes_of(PACKAGE)[0].properties
        assert (len(props["name"]), len(props["version"]), len(props["architecture"])) == (255, 128, 32)

    def test_nothing_emitted_from_a_hostile_document_exceeds_any_model_max_length(self):
        long = "x" * 600
        components = [
            _comp(long[:255], "1", cpe=long, licenses=[{"expression": long}]),
            _comp("lib", "1", purl="pkg:generic/lib@1", properties=[{"name": "tap:path", "value": long * 3}]),
            {
                "type": "operating-system",
                "name": "wolfi",
                "version": "1",
                "properties": [{"name": "syft:distro:prettyName", "value": long}],
            },
        ]
        batch = parse_cyclonedx(_doc(components, metadata={"tools": [{"name": long}]}), host_id=HOST)
        for node in batch.nodes:
            model = get_model_class(node.entity_type)
            for name, value in node.properties.items():
                limit = getattr(model._meta.get_field(name), "max_length", None)
                if limit and isinstance(value, str):
                    assert len(value) <= limit, (node.entity_type, name)


class TestNestedComponents:
    """The corpus has none; these make reading, ordering and counting them observable."""

    def test_a_nested_component_is_read_like_a_top_level_one(self):
        parent = _comp("parent", ref="parent", components=[_comp("child", ref="child")])
        nested = parse_cyclonedx(_doc([parent], [{"ref": "parent", "dependsOn": ["child"]}]), host_id=HOST)
        assert sorted(n.properties["name"] for n in nested.nodes_of(PACKAGE)) == ["child", "parent"]
        assert len(nested.edges_of("REQUIRES_PACKAGE__computing_core")) == 1
        assert nested.nodes_of(DOCUMENT)[0].properties["component_count"] == 2

    def test_nesting_does_not_change_which_packages_there_are(self):
        flat = parse_cyclonedx(_doc([_comp("parent", ref="parent"), _comp("child", ref="child")]), host_id=HOST)
        nested = parse_cyclonedx(
            _doc([_comp("parent", ref="parent", components=[_comp("child", ref="child")])]), host_id=HOST
        )
        assert flat.nodes_of(PACKAGE) == nested.nodes_of(PACKAGE)

    @pytest.mark.parametrize("value", [5, "x", {"a": 1}, True])
    def test_a_components_value_that_is_not_a_list_is_counted(self, value):
        batch = parse_cyclonedx(_doc([_comp("p", components=value)]), host_id=HOST)
        assert batch.report.skipped_components == {"nested components value is not a list": 1}
        assert [n.properties["name"] for n in batch.nodes_of(PACKAGE)] == ["p"]

    def test_a_nested_item_that_is_not_an_object_is_refused(self):
        with pytest.raises(SbomParseError, match="a component is not an object"):
            parse_cyclonedx(_doc([_comp("p", components=[5])]), host_id=HOST)

    def test_nested_components_count_toward_the_component_cap(self, monkeypatch):
        monkeypatch.setattr(parser_module, "MAX_COMPONENTS", 2)
        parent = _comp("p", components=[_comp("a"), _comp("b")])
        with pytest.raises(SbomParseError, match="component cap"):
            parse_cyclonedx(_doc([parent]), host_id=HOST)

    def test_reordering_nested_siblings_changes_nothing_but_the_digest(self):
        kids = [_comp(f"k{i}", ref=f"k{i}") for i in range(5)]
        one = parse_cyclonedx(_doc([_comp("p", ref="p", components=kids)]), host_id=HOST)
        two = parse_cyclonedx(_doc([_comp("p", ref="p", components=list(reversed(kids)))]), host_id=HOST)
        assert one.nodes_of(PACKAGE) == two.nodes_of(PACKAGE)


class TestPurlRules:
    def test_an_upper_case_scheme_is_read_and_the_purl_is_kept_as_given(self):
        batch = parse_cyclonedx(_doc([_comp(purl="PKG:apk/wolfi/p@1?arch=x86_64")]), host_id=HOST)
        props = batch.nodes_of(PACKAGE)[0].properties
        assert (props["ecosystem"], props["architecture"], props["purl"]) == (
            "apk",
            "x86_64",
            "PKG:apk/wolfi/p@1?arch=x86_64",
        )

    def test_a_repeated_qualifier_is_ignored_and_noted(self):
        batch = parse_cyclonedx(
            _doc([_comp(purl="pkg:apk/wolfi/p@1?arch=x86_64&arch=aarch64&upstream=base")]), host_id=HOST
        )
        assert batch.nodes_of(PACKAGE)[0].properties["architecture"] == ""
        assert [n.properties["name"] for n in batch.nodes_of(SOURCE)] == ["base"]
        assert any("'arch' appears more than once" in n for n in batch.report.notes)

    def test_qualifier_keys_are_case_insensitive(self):
        batch = parse_cyclonedx(_doc([_comp(purl="pkg:apk/wolfi/p@1?ARCH=x86_64")]), host_id=HOST)
        assert batch.nodes_of(PACKAGE)[0].properties["architecture"] == "x86_64"

    @pytest.mark.parametrize("bad", ["%zz", "%ff", "a b", "../x", "-x", "a/b", "%00"])
    def test_an_upstream_that_is_not_a_package_name_never_becomes_a_source_package(self, bad):
        batch = parse_cyclonedx(_doc([_comp("p", purl=f"pkg:apk/wolfi/p@1?upstream={bad}")]), host_id=HOST)
        assert [n.properties["name"] for n in batch.nodes_of(SOURCE)] == ["p"]
        assert batch.report.notes

    def test_an_encoded_upstream_is_decoded(self):
        batch = parse_cyclonedx(_doc([_comp("p", purl="pkg:apk/wolfi/p@1?upstream=open%73sl")]), host_id=HOST)
        assert [n.properties["name"] for n in batch.nodes_of(SOURCE)] == ["openssl"]

    def test_a_bad_origin_property_falls_through_to_the_qualifier(self):
        component = _comp(
            "p",
            purl="pkg:apk/wolfi/p@1?upstream=good",
            properties=[{"name": "syft:metadata:originPackage", "value": "not a name!"}],
        )
        batch = parse_cyclonedx(_doc([component]), host_id=HOST)
        assert [n.properties["name"] for n in batch.nodes_of(SOURCE)] == ["good"]


class TestPackageIdentityPolicy:
    """The key is (ecosystem, name, version): a purl namespace or an architecture is not identity."""

    def test_two_namespaces_of_one_name_and_version_are_one_package_and_the_conflict_is_reported(self):
        a = _comp("core", "1", ref="a", purl="pkg:maven/org.a/core@1")
        b = _comp("core", "1", ref="b", purl="pkg:maven/org.b/core@1")
        batch = parse_cyclonedx(_doc([a, b]), host_id=HOST)
        assert len(batch.nodes_of(PACKAGE)) == 1
        assert batch.nodes_of(PACKAGE)[0].properties["purl"] == "pkg:maven/org.a/core@1"
        assert batch.report.duplicate_components_collapsed == 1
        assert "maven/core/1: kept 'pkg:maven/org.a/core@1'" in batch.report.purl_conflicts[0]

    def test_two_architectures_of_one_deb_are_one_package(self):
        amd = _comp("curl", "8", ref="a", purl="pkg:deb/debian/curl@8?arch=amd64")
        arm = _comp("curl", "8", ref="b", purl="pkg:deb/debian/curl@8?arch=arm64")
        batch = parse_cyclonedx(_doc([arm, amd]), host_id=HOST)
        assert len(batch.nodes_of(PACKAGE)) == 1
        assert batch.nodes_of(PACKAGE)[0].properties["architecture"] == "amd64"
