"""Tests for `parse_cyclonedx` (req-computing-core-sbom-parse and the package/dependency ACIDs it feeds).

The corpus is the attested tap-web SBOM, unmodified (tests/corpus/): image `sha256:a9149a88...`,
CycloneDX 1.7, Syft 1.51.0, 192 components. Every number asserted here can be re-read from it.
No test needs a database: the parser is pure.
"""

import hashlib
import json
import random
import subprocess
import sys
import uuid
from collections import Counter
from pathlib import Path

import pytest
from tap_plugin.computing_core.sbom import SbomBatch, SbomParseError, parse_cyclonedx
from tap_plugin.computing_core.sbom import parser as parser_module

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


class TestPureAndDjangoFree:
    """req-computing-core-sbom-parse-1."""

    def test_the_sbom_package_imports_and_parses_with_django_blocked_and_nothing_opened(self, corpus_bytes: bytes):
        script = r"""
import builtins, io, json, socket, sys, time
sys.path[:] = json.loads(sys.argv[1])

class Block:
    def find_spec(self, name, path=None, target=None):
        if name == "django" or name.startswith("django."):
            raise ImportError(f"Django is blocked: {name}")

sys.meta_path.insert(0, Block())
from tap_plugin.computing_core.sbom import parse_cyclonedx, build_cyclonedx

data = sys.stdin.buffer.read()

def refuse(*args, **kwargs):
    raise AssertionError("the parser opened a file, a socket or read the clock")

builtins.open = io.open = socket.socket = time.time = time.monotonic = time.time_ns = refuse
batch = parse_cyclonedx(data, host_id="01a13c38-4f5e-735c-9cf2-1f159f4282b6")
assert len(batch.nodes) > 100
assert not [m for m in sys.modules if m == "django" or m.startswith("django.")]
print("clean", len(batch.nodes), len(batch.edges))
"""
        result = subprocess.run(  # noqa: S603 — fixed argv, the interpreter running this test
            [sys.executable, "-I", "-c", script, json.dumps(sys.path)],
            input=corpus_bytes,
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr.decode()
        assert result.stdout.decode().startswith("clean")

    def test_the_block_is_real(self):
        """The guard above would pass vacuously if the blocker never fired; prove Django IS refused."""
        script = (
            "import sys\n"
            "class B:\n"
            "    def find_spec(self, n, p=None, t=None):\n"
            "        if n == 'django' or n.startswith('django.'): raise ImportError(n)\n"
            "sys.meta_path.insert(0, B())\n"
            "try:\n    import django\nexcept ImportError:\n    print('blocked')\n"
        )
        result = subprocess.run([sys.executable, "-I", "-c", script], capture_output=True, check=False)  # noqa: S603
        assert result.stdout.decode().strip() == "blocked"


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

    def test_every_node_property_set_is_valid_for_its_model_field_names(self, batch: SbomBatch):
        allowed = {
            PACKAGE: {
                "ecosystem",
                "name",
                "version",
                "architecture",
                "purl",
                "cpe",
                "cpe_candidates",
                "license",
                "source_document",
            },
            LIBRARY: {"ecosystem", "name", "version", "purl", "cpe", "license", "source_kind", "source_url", "path"},
            SOURCE: {"ecosystem", "name", "version"},
            OS: {"os_id", "version_id", "build_id", "name"},
            DOCUMENT: {
                "content_digest",
                "format",
                "spec_version",
                "serial_number",
                "revision",
                "subject_digest",
                "produced_at",
                "generator",
                "component_count",
            },
        }
        for node in batch.nodes:
            assert set(node.properties) <= allowed[node.entity_type], node.entity_type


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


class TestUnreadableIsRefusedNotEmpty:
    """req-computing-core-sbom-parse-6."""

    @pytest.mark.parametrize(
        ("body", "why"),
        [
            (b"", "empty"),
            (b"   \n", "empty"),
            (b"not json at all", "not JSON"),
            (b"\xff\xfe\x00garbage", "not JSON"),
            (b"[1, 2, 3]", "top level is list"),
            (b'{"hello": "world"}', "bomFormat"),
            (b'{"bomFormat": "CycloneDX", "specVersion": "1.6"}', "no components array"),
            (b'{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}', "no components"),
            (b'{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [], "x": NaN}', "NaN"),
            (b'{"bomFormat": "CycloneDX", "bomFormat": "CycloneDX"}', "appears twice"),
        ],
    )
    def test_each_is_refused_naming_why(self, body: bytes, why: str):
        with pytest.raises(SbomParseError) as raised:
            parse_cyclonedx(body, host_id=HOST)
        assert why.split()[0].lower() in str(raised.value).lower()

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
