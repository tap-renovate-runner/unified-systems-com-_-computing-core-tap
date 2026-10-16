"""Tests for `build_cyclonedx` (req-computing-core-sbom-build).

The builder is the parser run backwards, so most of these start from the corpus: parse it, hand
the parsed rows to the builder, and read the result back.
"""

import builtins
import io
import json
import os
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

import pytest
from tap_plugin.computing_core.sbom import SbomBatch, build_cyclonedx, parse_cyclonedx

CORPUS = Path(__file__).resolve().parent / "corpus" / "tap-web-latest-arm64.cdx.json"
HOST = str(uuid.UUID("01a13c38-4f5e-735c-9cf2-1f159f4282b6"))

PACKAGE = "computing_core__package"
LIBRARY = "computing_core__library"
OS = "computing_core__operating_system"
DOCUMENT = "computing_core__sbom_document"
REQUIRES = "REQUIRES_PACKAGE__computing_core"


@pytest.fixture(scope="module")
def corpus_bytes() -> bytes:
    return CORPUS.read_bytes()


@pytest.fixture(scope="module")
def batch(corpus_bytes: bytes) -> SbomBatch:
    return parse_cyclonedx(corpus_bytes, host_id=HOST)


def _inputs(batch: SbomBatch) -> dict:
    """What a caller reads off the grid for one host, from a parsed batch: the property mappings."""
    packages = [dict(n.properties) for n in batch.nodes_of(PACKAGE)]
    key_of = {
        n.ref: (n.properties["ecosystem"], n.properties["name"], n.properties["version"])
        for n in batch.nodes_of(PACKAGE)
    }
    return {
        "packages": packages,
        "libraries": [dict(n.properties) for n in batch.nodes_of(LIBRARY)],
        "operating_system": dict(batch.nodes_of(OS)[0].properties),
        "requires": [(key_of[e.from_ref], key_of[e.to_ref]) for e in batch.edges_of(REQUIRES)],
    }


@pytest.fixture(scope="module")
def built(batch: SbomBatch) -> bytes:
    return build_cyclonedx(**_inputs(batch))


class TestTheMatchingFieldsAreEmitted:
    """req-computing-core-sbom-build-1."""

    def test_it_is_cyclonedx_1_6(self, built: bytes):
        document = json.loads(built)
        assert (document["bomFormat"], document["specVersion"]) == ("CycloneDX", "1.6")

    def test_each_package_carries_its_whole_purl_cpe_and_every_candidate(self, built: bytes, batch: SbomBatch):
        components = {c["purl"]: c for c in json.loads(built)["components"] if c.get("purl")}
        for node in batch.nodes_of(PACKAGE):
            props = node.properties
            component = components[props["purl"]]
            assert component["cpe"] == props["cpe"]
            written = [p["value"] for p in component.get("properties", []) if p["name"] == "syft:cpe23"]
            assert written == props["cpe_candidates"]

    def test_libssl3_has_its_three_candidates_as_syft_cpe23(self, built: bytes):
        (libssl3,) = [c for c in json.loads(built)["components"] if c["name"] == "libssl3"]
        assert "upstream=openssl" in libssl3["purl"]
        assert [p["name"] for p in libssl3["properties"]] == ["syft:cpe23"] * 3

    def test_the_libraries_are_included_the_provider_with_its_cpe(self, built: bytes):
        components = {c["name"]: c for c in json.loads(built)["components"]}
        assert {"openssl-fips-provider", "uv", "uvx"} <= set(components)
        assert components["openssl-fips-provider"]["cpe"] == "cpe:2.3:a:openssl:openssl:3.5.8:*:*:*:*:*:*:*"

    def test_the_operating_system_carries_its_distro_properties(self, built: bytes):
        (wolfi,) = [c for c in json.loads(built)["components"] if c["type"] == "operating-system"]
        assert {p["name"]: p["value"] for p in wolfi["properties"]} == {
            "syft:distro:id": "wolfi",
            "syft:distro:prettyName": "Wolfi",
            "syft:distro:versionID": "20230201",
        }

    def test_requires_package_becomes_dependencies(self, built: bytes, batch: SbomBatch):
        document = json.loads(built)
        assert sum(len(d["dependsOn"]) for d in document["dependencies"]) == len(batch.edges_of(REQUIRES)) == 450
        refs = {c["bom-ref"] for c in document["components"]}
        assert all(d["ref"] in refs and set(d["dependsOn"]) <= refs for d in document["dependencies"])

    def test_every_bom_ref_is_unique(self, built: bytes):
        refs = [c["bom-ref"] for c in json.loads(built)["components"]]
        assert len(refs) == len(set(refs))

    def test_a_package_with_no_purl_is_written_with_a_minimal_purl(self):
        """Without one a reader could not tell its package manager."""
        document = json.loads(build_cyclonedx([{"ecosystem": "apk", "name": "zlib", "version": "1"}]))
        assert document["components"][0]["purl"] == "pkg:apk/zlib@1"
        assert document["components"][0]["bom-ref"] == "pkg:apk/zlib@1"

    def test_duplicate_package_keys_are_one_component_whatever_the_order(self):
        one = {"ecosystem": "apk", "name": "zlib", "version": "1", "purl": "pkg:apk/wolfi/zlib@1?arch=x86_64"}
        two = {**one, "purl": "pkg:apk/wolfi/zlib@1?arch=aarch64"}
        forward, backward = build_cyclonedx([one, two]), build_cyclonedx([two, one])
        assert forward == backward
        components = json.loads(forward)["components"]
        assert [c["purl"] for c in components] == ["pkg:apk/wolfi/zlib@1?arch=aarch64"]

    def test_a_lone_surrogate_in_an_input_cannot_break_the_encoding(self):
        document = build_cyclonedx([{"ecosystem": "apk", "name": "z\ud800", "version": "1"}])
        assert document.isascii()

    def test_non_ascii_text_survives_as_an_escape(self):
        document = build_cyclonedx([{"ecosystem": "pypi", "name": "caf\u00e9", "version": "1"}])
        assert document.isascii()
        assert json.loads(document)["components"][0]["name"] == "caf\u00e9"


class TestRoundTrip:
    """req-computing-core-sbom-build-2."""

    def test_parse_of_build_of_parse_is_parse(self, batch: SbomBatch, built: bytes):
        again = parse_cyclonedx(built, host_id=HOST)

        def rows(b: SbomBatch):
            nodes = [n for n in b.nodes if n.entity_type != DOCUMENT]
            edges = [e for e in b.edges if e.edge_type != "DESCRIBES_HOST__computing_core"]
            return nodes, edges

        assert rows(again) == rows(batch)

    def test_the_source_package_edges_survive_through_the_upstream_qualifier(self, batch: SbomBatch, built: bytes):
        again = parse_cyclonedx(built, host_id=HOST)
        assert len(again.nodes_of("computing_core__source_package")) == 72
        assert len(again.edges_of("DERIVES_FROM_SOURCE_PACKAGE__computing_core")) == 102
        assert "syft:metadata:originPackage" not in built.decode()

    def test_a_package_with_no_purl_comes_back_as_the_same_package_with_its_own_origin(self):
        """The minimal purl is added, and with no `upstream=` the source package is the package's own name."""
        row = {"ecosystem": "apk", "name": "libssl3", "version": "3", "architecture": "", "cpe_candidates": []}
        again = parse_cyclonedx(build_cyclonedx([row]), host_id=HOST)
        assert [n.properties["name"] for n in again.nodes_of(PACKAGE)] == ["libssl3"]
        assert [n.properties["name"] for n in again.nodes_of("computing_core__source_package")] == ["libssl3"]

    def test_the_document_row_differs_because_the_bytes_do(self, batch: SbomBatch, built: bytes):
        again = parse_cyclonedx(built, host_id=HOST)
        assert (
            again.nodes_of(DOCUMENT)[0].properties["content_digest"]
            != batch.nodes_of(DOCUMENT)[0].properties["content_digest"]
        )
        assert again.nodes_of(DOCUMENT)[0].properties["spec_version"] == "1.6"


class TestThrowawayAndDeterministic:
    """req-computing-core-sbom-build-4."""

    def test_two_calls_on_the_same_inputs_return_identical_bytes(self, batch: SbomBatch):
        inputs = _inputs(batch)
        first = build_cyclonedx(**inputs)
        second = build_cyclonedx(**inputs)
        assert first == second

    def test_input_order_does_not_change_the_bytes(self, batch: SbomBatch):
        inputs = _inputs(batch)
        reversed_inputs = {
            "packages": list(reversed(inputs["packages"])),
            "libraries": list(reversed(inputs["libraries"])),
            "operating_system": inputs["operating_system"],
            "requires": list(reversed(inputs["requires"])),
        }
        assert build_cyclonedx(**reversed_inputs) == build_cyclonedx(**inputs)

    def test_it_writes_no_file_and_opens_nothing(self, batch: SbomBatch, monkeypatch):
        def refuse(*args, **kwargs):
            raise AssertionError("the builder opened a file")

        inputs = _inputs(batch)
        monkeypatch.setattr(builtins, "open", refuse)
        monkeypatch.setattr(io, "open", refuse)
        monkeypatch.setattr(os, "open", refuse)
        assert build_cyclonedx(**inputs)

    def test_it_takes_the_inputs_without_changing_them(self, batch: SbomBatch):
        inputs = _inputs(batch)
        before = json.dumps(inputs, sort_keys=True, default=list)
        build_cyclonedx(**inputs)
        assert json.dumps(inputs, sort_keys=True, default=list) == before


def _grype() -> str | None:
    """A Grype binary named by `GRYPE_BIN`, or one on PATH; None when there is none."""
    named = os.environ.get("GRYPE_BIN")
    return named if named and Path(named).is_file() else shutil.which("grype")


def _matches(grype: str, document: bytes, workdir: Path, name: str) -> set[tuple[str, str, str]]:
    path = workdir / name
    path.write_bytes(document)
    # The one place a test runs a program: the Grype binary the operator named, with fixed
    # arguments and a file this test just wrote. Nothing from the document reaches the command line.
    # GRYPE_DB_AUTO_UPDATE=false: the test must not reach the network; it uses the database the
    # operator already has (a missing one fails the test loudly rather than skipping it).
    env = {**os.environ, "GRYPE_DB_AUTO_UPDATE": "false", "GRYPE_CHECK_FOR_APP_UPDATE": "false"}
    result = subprocess.run(  # noqa: S603  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit, python.lang.security.audit.dangerous-subprocess-use-tainted-env-args.dangerous-subprocess-use-tainted-env-args
        [grype, f"sbom:{path}", "-o", "json", "-q"],
        capture_output=True,
        check=True,
        text=True,
        env=env,
    )
    found = json.loads(result.stdout)["matches"]
    return {(m["vulnerability"]["id"], m["artifact"]["name"], m["artifact"]["version"]) for m in found}


@pytest.mark.skipif(_grype() is None, reason="no Grype binary: set GRYPE_BIN or put grype on PATH (v0.120.1 was used)")
class TestTheScannerAgrees:
    """req-computing-core-sbom-build-3. Skipped where there is no Grype, which includes the plugin's CI."""

    def test_the_built_document_matches_what_the_corpus_matches(
        self, batch: SbomBatch, built: bytes, corpus_bytes: bytes
    ):
        grype = _grype()
        assert grype
        with tempfile.TemporaryDirectory() as work:
            on_corpus = _matches(grype, corpus_bytes, Path(work), "corpus.cdx.json")
            on_built = _matches(grype, built, Path(work), "built.cdx.json")
        assert on_corpus, "the corpus matched nothing: the vulnerability database is empty or unreadable"
        assert on_built == on_corpus
