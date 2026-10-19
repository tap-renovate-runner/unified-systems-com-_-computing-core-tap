"""Tests for `parse_cyclonedx_vulnerabilities` (req-computing-core-sbom-vulns).

The corpus is revision 2 of the attested tap-web SBOM (tests/corpus/tap-web-rev2-a9149a88.cdx.json):
the exact predicate bytes `gh attestation verify` returned for image `sha256:a9149a88...`, signed by
`sbom-vulnerability-evidence.yml`, CycloneDX 1.7, `serialNumber urn:uuid:90f083a0-...`, `version` 2,
192 components, 94 vulnerability entries naming 27 ids. It is the same document lineage as the
revision-1 corpus the parser tests use. Every number asserted here can be re-read from it.

No test needs a database: the reader is pure. The cases the real document cannot show (a KEV
listing, a VEX state, entries that disagree) are synthetic and labelled so.
"""

from __future__ import annotations

import copy
import hashlib
import json
import multiprocessing
import random
import uuid
from collections import Counter
from pathlib import Path

import pytest
from tap_plugin.computing_core.sbom import (
    SbomParseError,
    Verification,
    VulnerabilityBatch,
    parse_cyclonedx,
    parse_cyclonedx_vulnerabilities,
)
from tap_plugin.computing_core.sbom import vulnerabilities as vulns_module
from tap_plugin.computing_core.tests import _django_free_probe as probe

VERIFIED = Verification("verified", signer="ci@example.org")
REFUSED = Verification("refused", "signer-identity")
UNCHECKED = Verification("not-observable", "no attestation was published")
CORPUS = Path(__file__).resolve().parent / "corpus" / "tap-web-rev2-a9149a88.cdx.json"
REV3 = Path(__file__).resolve().parent / "corpus" / "tap-web-rev3-a9149a88.cdx.json"
REV1 = Path(__file__).resolve().parent / "corpus" / "tap-web-latest-arm64.cdx.json"
HOST = str(uuid.UUID("01a13c38-4f5e-735c-9cf2-1f159f4282b6"))
PACKAGE = "computing_core__package"
LIBRARY = "computing_core__library"
OS = "computing_core__operating_system"


@pytest.fixture(scope="module")
def corpus_bytes() -> bytes:
    return CORPUS.read_bytes()


@pytest.fixture(scope="module")
def corpus(corpus_bytes: bytes) -> dict:
    return json.loads(corpus_bytes)


@pytest.fixture(scope="module")
def batch(corpus_bytes: bytes) -> VulnerabilityBatch:
    return parse_cyclonedx_vulnerabilities(corpus_bytes, verification=VERIFIED)


def _spawned(function, *args):
    with multiprocessing.get_context("spawn").Pool(1) as pool:
        return pool.apply(function, args)


def _component(name: str = "zlib", version: str = "1.0", ref: str | None = None, purl: str | None = None) -> dict:
    purl = purl or f"pkg:apk/wolfi/{name}@{version}"
    return {"bom-ref": ref or purl, "type": "library", "name": name, "version": version, "purl": purl}


def _entry(vuln_id: str = "CVE-2026-0001", ref: str = "pkg:apk/wolfi/zlib@1.0", **extra) -> dict:
    return {"id": vuln_id, "affects": [{"ref": ref, "versions": [{"version": "1.0", "status": "affected"}]}], **extra}


def _doc(vulnerabilities: list | None, components: list[dict] | None = None, **top) -> bytes:
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 2,
        "serialNumber": "urn:uuid:90f083a0-a7b6-4183-a41d-ad1bb111feeb",
        "metadata": {
            "timestamp": "2026-10-16T19:30:31Z",
            "component": {
                "type": "container",
                "name": "ghcr.io/example/app",
                "version": "sha256:" + "a" * 64,
            },
        },
        "components": components if components is not None else [_component()],
        **top,
    }
    if vulnerabilities is not None:
        document["vulnerabilities"] = vulnerabilities
    return json.dumps(document).encode()


def _read(data: bytes) -> VulnerabilityBatch:
    return parse_cyclonedx_vulnerabilities(data, verification=VERIFIED)


def _record(batch: VulnerabilityBatch, vuln_id: str):
    return next(v for v in batch.vulnerabilities if v.vuln_id == vuln_id)


class TestPureAndDjangoFree:
    """req-computing-core-sbom-vulns-1."""

    @pytest.mark.spec("req-computing-core-sbom-vulns-1")
    def test_the_reader_imports_and_runs_with_django_blocked_and_nothing_opened(self):
        vulnerabilities, matches, django_modules = _spawned(probe.read_vulnerabilities_with_django_blocked, str(CORPUS))
        assert (vulnerabilities, matches) == (27, 94)
        assert django_modules == []

    @pytest.mark.spec("req-computing-core-sbom-vulns-1")
    def test_the_block_is_real(self):
        assert _spawned(probe.django_is_refused) is True


class TestOnlyAVerifiedDocumentIsRead:
    """req-computing-core-sbom-vulns-2."""

    @pytest.mark.spec("req-computing-core-sbom-vulns-2")
    @pytest.mark.parametrize("verification", [REFUSED, UNCHECKED])
    def test_a_refused_or_unchecked_document_is_not_read(self, corpus_bytes, verification, monkeypatch):
        monkeypatch.setattr(vulns_module, "_load", lambda data: pytest.fail("the body was read"))
        with pytest.raises(ValueError, match="is not parsed; use record_document"):
            parse_cyclonedx_vulnerabilities(corpus_bytes, verification=verification)

    @pytest.mark.spec("req-computing-core-sbom-vulns-2")
    def test_omitting_verification_is_a_type_error_not_a_default(self, corpus_bytes):
        with pytest.raises(TypeError, match="verification"):
            parse_cyclonedx_vulnerabilities(corpus_bytes)  # type: ignore[call-arg]

    @pytest.mark.spec("req-computing-core-sbom-vulns-2")
    @pytest.mark.parametrize("not_a_verification", [None, "verified", True, {"outcome": "verified"}])
    def test_anything_that_is_not_a_verification_is_refused_before_a_byte_is_read(
        self, not_a_verification, monkeypatch
    ):
        monkeypatch.setattr(vulns_module, "_load", lambda data: pytest.fail("the body was read"))
        with pytest.raises(ValueError, match="must be a Verification"):
            parse_cyclonedx_vulnerabilities(b"{}", verification=not_a_verification)  # type: ignore[arg-type]


class TestNeverScannedIsRefusedScannedCleanIsEmpty:
    """req-computing-core-sbom-vulns-3."""

    @pytest.mark.spec("req-computing-core-sbom-vulns-3")
    def test_revision_one_of_the_real_document_was_never_scanned(self):
        with pytest.raises(SbomParseError, match="never scanned"):
            _read(REV1.read_bytes())

    @pytest.mark.spec("req-computing-core-sbom-vulns-3")
    def test_an_empty_array_is_a_scan_that_found_nothing(self):
        batch = _read(_doc([]))
        assert (batch.vulnerabilities, batch.matches, batch.detectors) == ((), (), ())
        assert batch.report.entries == 0

    @pytest.mark.spec("req-computing-core-sbom-vulns-3")
    @pytest.mark.parametrize("value", [{}, "none", 7])
    def test_a_vulnerabilities_value_that_is_not_an_array_is_refused(self, value):
        with pytest.raises(SbomParseError, match="not an array"):
            _read(_doc(value))


class TestAMatchNamesANodeTheParserMakes:
    """req-computing-core-sbom-vulns-4."""

    @pytest.mark.spec("req-computing-core-sbom-vulns-4")
    def test_every_match_is_a_node_parse_cyclonedx_emits_for_the_same_bytes(self, corpus_bytes, batch):
        parsed = parse_cyclonedx(corpus_bytes, host_id=HOST, verification=VERIFIED)
        emitted = {
            (row.entity_type, tuple(row.properties[f] for f in _fields(row.entity_type)))
            for row in parsed.nodes
            if row.entity_type in (PACKAGE, LIBRARY, OS)
        }
        named = {(m.component.entity_type, m.component.values) for m in batch.matches}
        assert named
        assert named <= emitted

    @pytest.mark.spec("req-computing-core-sbom-vulns-4")
    def test_the_key_fields_are_the_models_natural_key(self, batch):
        from tap_grid.registry import get_model_class

        for entity_type in {m.component.entity_type for m in batch.matches}:
            fields = next(m.component.fields for m in batch.matches if m.component.entity_type == entity_type)
            assert fields == get_model_class(entity_type).NATURAL_KEY

    @pytest.mark.spec("req-computing-core-sbom-vulns-4")
    def test_an_operating_system_is_named_by_its_distro_key(self):
        os_component = {
            "bom-ref": "os-1",
            "type": "operating-system",
            "name": "wolfi",
            "version": "20230201",
            "properties": [
                {"name": "syft:distro:id", "value": "wolfi"},
                {"name": "syft:distro:versionID", "value": "20230201"},
            ],
        }
        match = _read(_doc([_entry(ref="os-1")], [os_component])).matches[0]
        assert match.component.entity_type == OS
        assert match.component.key == {"os_id": "wolfi", "version_id": "20230201", "build_id": ""}


def _fields(entity_type: str) -> tuple[str, ...]:
    return {
        PACKAGE: ("ecosystem", "name", "version"),
        LIBRARY: ("ecosystem", "name", "version"),
        OS: ("os_id", "version_id", "build_id"),
    }[entity_type]


class TestTheRealDocument:
    """req-computing-core-sbom-vulns-5."""

    @pytest.mark.spec("req-computing-core-sbom-vulns-5")
    def test_the_counts(self, batch):
        assert len(batch.vulnerabilities) == 27
        assert len(batch.matches) == 94
        assert Counter(m.component.entity_type for m in batch.matches) == {PACKAGE: 81, LIBRARY: 13}
        assert batch.report.entries == 94
        assert batch.report.skipped_entries == {}
        assert batch.report.skipped_matches == {}
        assert batch.report.duplicate_matches_collapsed == 0

    @pytest.mark.spec("req-computing-core-sbom-vulns-5")
    def test_the_detector_and_the_document_facts(self, batch):
        assert [(d.name, d.version) for d in batch.detectors] == [("grype", "0.120.1")]
        info = batch.document
        assert info.serial_number == "urn:uuid:90f083a0-a7b6-4183-a41d-ad1bb111feeb"
        assert info.revision == 2
        assert info.subject_name == "ghcr.io/unified-systems-com/tap-web"
        assert info.subject_digest == "sha256:a9149a88a6239fc7a5351d9854fbff42448d2ed28cc71951a4c2aa2f4aca7750"
        assert info.produced_at == "2026-10-16T19:30:31Z"
        assert info.previous_content_digest == (
            "sha256:e96d02cdbfabc35957456f92ac07fd2fe219f9e512921dc3283b8a10fedd397e"
        )
        assert info.scanner_db_built == "2026-10-16T06:29:51Z"

    @pytest.mark.spec("req-computing-core-sbom-vulns-5")
    def test_one_vulnerability_read_end_to_end(self, batch):
        record = _record(batch, "CVE-2025-15367")
        assert record.aliases == ()
        assert record.description.startswith("The poplib module")
        assert (record.cvss.score, record.cvss.version, record.cvss.source) == (5.9, "4.0", "PSF")
        assert record.cwes == ("CWE-77",)
        assert (record.ssvc.exploitation, record.ssvc.automatable, record.ssvc.technical_impact) == (
            "none",
            "no",
            "total",
        )
        assert record.ssvc.assessed_at == "2026-01-22T04:55:33.480214Z"
        assert (record.epss.score, record.epss.percentile, record.epss.date) == (0.00369, 0.29122, "2026-10-15")
        assert record.kev.listed is False
        assert record.kev.catalog_version == "2026.10.16"
        assert record.record_updated_at == "2026-02-26T14:44:41.341Z"
        (match,) = [m for m in batch.matches_of("CVE-2025-15367") if m.component.name == "python-3.14"]
        assert match.component.key == {"ecosystem": "apk", "name": "python-3.14", "version": "3.14.8_git20261001-r0"}
        assert (match.fixed_versions, match.fix_state) == (None, "unknown")

    @pytest.mark.spec("req-computing-core-sbom-vulns-5")
    def test_a_fixed_match_carries_its_versions(self, batch):
        fixed = [m for m in batch.matches if m.fixed_versions]
        assert len(fixed) == 67
        assert all(m.fix_state == "fixed" for m in fixed)
        assert all(list(m.fixed_versions) == sorted(m.fixed_versions) for m in fixed)

    @pytest.mark.spec("req-computing-core-sbom-vulns-5")
    def test_an_advisory_alias_is_kept(self, batch):
        record = _record(batch, "CVE-2026-49264")
        assert record.aliases == ("GHSA-hj66-6f7g-4r5v",)


class TestAbsentIsDeclaredNeverInvented:
    """req-computing-core-sbom-vulns-6."""

    @pytest.mark.spec("req-computing-core-sbom-vulns-6")
    def test_a_ghsa_only_record_has_no_cve_record_facts(self, batch):
        ghsa = [v for v in batch.vulnerabilities if v.vuln_id.startswith("GHSA-")]
        assert ghsa
        for record in ghsa:
            assert record.ssvc is None
            assert record.epss is None
            assert record.record_updated_at is None

    @pytest.mark.spec("req-computing-core-sbom-vulns-6")
    def test_cwes_are_empty_only_when_the_cve_record_was_read(self):
        read = _read(_doc([_entry(properties=[{"name": "tap:cve-record:status", "value": "observed"}], cwes=[])]))
        unread = _read(_doc([_entry(cwes=[])]))
        assert read.vulnerabilities[0].cwes == ()
        assert unread.vulnerabilities[0].cwes is None

    @pytest.mark.spec("req-computing-core-sbom-vulns-6")
    def test_a_kev_answer_of_not_observed_is_none_not_false(self):
        for props in ([{"name": "tap:kev:listed", "value": "not-observed"}], []):
            assert _read(_doc([_entry(properties=props)])).vulnerabilities[0].kev is None

    @pytest.mark.spec("req-computing-core-sbom-vulns-6")
    def test_a_record_without_ratings_has_no_cvss_and_no_epss(self):
        record = _read(_doc([_entry()])).vulnerabilities[0]
        assert (record.cvss, record.epss, record.ssvc, record.description) == (None, None, None, None)

    @pytest.mark.spec("req-computing-core-sbom-vulns-6")
    def test_revision_two_predates_title_publication_time_and_record_link(self, batch):
        for record in batch.vulnerabilities:
            assert (record.title, record.published_at, record.record_url, record.advisories) == (None, None, None, ())

    @pytest.mark.spec("req-computing-core-sbom-vulns-6")
    def test_an_epss_outside_zero_to_one_is_left_out_with_a_note(self):
        rating = {"source": {"name": "FIRST"}, "score": 7, "method": "other", "justification": "EPSS"}
        batch = _read(_doc([_entry(ratings=[rating])]))
        assert batch.vulnerabilities[0].epss is None
        assert any("EPSS score" in n for n in batch.report.notes)


class TestOneCvssRule:
    """req-computing-core-sbom-vulns-7."""

    @staticmethod
    def _rating(source: str, method: str, score: float, vector: str = "v") -> dict:
        return {"source": {"name": source}, "method": method, "score": score, "vector": vector}

    @pytest.mark.spec("req-computing-core-sbom-vulns-7")
    def test_the_newest_version_wins_over_a_higher_older_score(self):
        ratings = [
            self._rating("nvd", "CVSSv2", 10.0),
            self._rating("nvd", "CVSSv31", 5.0),
            self._rating("a", "CVSSv3", 9.8),
        ]
        cvss = _read(_doc([_entry(ratings=ratings)])).vulnerabilities[0].cvss
        assert (cvss.version, cvss.score) == ("3.1", 5.0)

    @pytest.mark.spec("req-computing-core-sbom-vulns-7")
    def test_within_a_version_the_highest_score_then_the_lowest_source_name(self):
        ratings = [
            self._rating("zeta", "CVSSv31", 7.5),
            self._rating("beta", "CVSSv31", 9.1),
            self._rating("alpha", "CVSSv31", 9.1),
        ]
        cvss = _read(_doc([_entry(ratings=ratings)])).vulnerabilities[0].cvss
        assert (cvss.score, cvss.source) == (9.1, "alpha")

    @pytest.mark.spec("req-computing-core-sbom-vulns-7")
    def test_non_cvss_and_out_of_range_ratings_are_not_cvss(self):
        ratings = [
            {"source": {"name": "CISA-ADP"}, "method": "SSVC", "vector": "x"},
            {"source": {"name": "FIRST"}, "method": "other", "score": 0.5, "justification": "EPSS"},
            self._rating("nvd", "CVSSv31", 11.0),
            {"method": "CVSSv31", "score": 5.0},
        ]
        assert _read(_doc([_entry(ratings=ratings)])).vulnerabilities[0].cvss is None

    @pytest.mark.spec("req-computing-core-sbom-vulns-7")
    def test_a_missing_vector_is_none_not_blank(self):
        rating = {"source": {"name": "nvd"}, "method": "CVSSv31", "score": 5.0}
        assert _read(_doc([_entry(ratings=[rating])])).vulnerabilities[0].cvss.vector is None


class TestKevAndFixAreReadAsPublished:
    """req-computing-core-sbom-vulns-8. Synthetic: the real document lists no KEV vulnerability."""

    @staticmethod
    def _props(**pairs: str) -> list[dict]:
        return [{"name": f"tap:{k.replace('__', ':').replace('_', '-')}", "value": v} for k, v in pairs.items()]

    @pytest.mark.spec("req-computing-core-sbom-vulns-8")
    def test_a_listed_entry_carries_the_catalogs_facts(self):
        props = self._props(
            kev__listed="true",
            kev__date_added="2026-09-01",
            kev__due_date="2026-09-22",
            kev__required_action="Apply updates.",
            kev__ransomware_use="Known",
            kev__catalog_version="2026.10.16",
        )
        kev = _read(_doc([_entry(properties=props)])).vulnerabilities[0].kev
        assert (kev.listed, kev.date_added, kev.due_date, kev.required_action, kev.ransomware_use) == (
            True,
            "2026-09-01",
            "2026-09-22",
            "Apply updates.",
            "Known",
        )
        assert kev.catalog_version == "2026.10.16"

    @pytest.mark.spec("req-computing-core-sbom-vulns-8")
    def test_a_date_that_is_not_a_date_is_left_none_with_a_note(self):
        props = self._props(kev__listed="true", kev__date_added="Sept 1", kev__due_date="2026-02-30")
        batch = _read(_doc([_entry(properties=props)]))
        kev = batch.vulnerabilities[0].kev
        assert (kev.listed, kev.date_added, kev.due_date) == (True, None, None)
        assert len([n for n in batch.report.notes if "date" in n]) == 2

    @pytest.mark.spec("req-computing-core-sbom-vulns-8")
    def test_the_catalog_version_of_a_listing_falls_back_to_the_documents(self):
        props = self._props(kev__listed="true")
        data = json.loads(_doc([_entry(properties=props)]))
        data["metadata"]["properties"] = [{"name": "tap:kev:catalog-version", "value": "2026.10.16"}]
        assert _read(json.dumps(data).encode()).vulnerabilities[0].kev.catalog_version == "2026.10.16"

    @pytest.mark.spec("req-computing-core-sbom-vulns-8")
    @pytest.mark.parametrize(
        ("props", "expected"),
        [
            ({"fix__state": "fixed", "fix__versions": "3.1.2,3.0.10"}, (("3.0.10", "3.1.2"), "fixed")),
            ({"fix__state": "not-fixed"}, ((), "not-fixed")),
            ({"fix__state": "wont-fix"}, ((), "wont-fix")),
            ({"fix__state": "unknown"}, (None, "unknown")),
            ({}, (None, None)),
        ],
    )
    def test_fixed_versions_say_whether_a_fix_is_known(self, props, expected):
        match = _read(_doc([_entry(properties=self._props(**props))])).matches[0]
        assert (match.fixed_versions, match.fix_state) == expected


class TestSkipsAreCounted:
    """req-computing-core-sbom-vulns-9."""

    @pytest.mark.spec("req-computing-core-sbom-vulns-9")
    def test_each_kind_of_skip_has_its_reason(self):
        entries = [
            _entry("CVE-2026-0001"),
            {"affects": []},
            "not an object",
            _entry("X" * 129),
            _entry("CVE-2026-0002", ref="pkg:apk/wolfi/missing@1"),
            _entry("CVE-2026-0003", ref="u"),
            {"id": "CVE-2026-0004"},
            {
                "id": "CVE-2026-0005",
                "affects": [
                    {"ref": "pkg:apk/wolfi/zlib@1.0", "versions": [{"version": "1.0", "status": "unaffected"}]}
                ],
            },
        ]
        unreadable = {"bom-ref": "u", "type": "file", "name": "readme", "version": "1"}
        batch = _read(_doc(entries, [_component(), unreadable]))
        assert [m.vuln_id for m in batch.matches] == ["CVE-2026-0001"]
        assert batch.report.entries == 8
        assert batch.report.skipped_entries == {
            "entry is not an object": 1,
            "no id": 1,
            "id longer than 128 characters": 1,
        }
        assert batch.report.skipped_matches == {
            "affects names no listed component": 1,
            "affects a component that becomes no node (no purl and CycloneDX type 'file' is not software)": 1,
            "entry affects no component": 1,
            "affects lists no affected version": 1,
        }

    @pytest.mark.spec("req-computing-core-sbom-vulns-9")
    def test_a_repeated_pair_is_one_match_and_counted(self):
        entries = [_entry(), _entry()]
        batch = _read(_doc(entries))
        assert len(batch.matches) == 1
        assert batch.report.duplicate_matches_collapsed == 1

    @pytest.mark.spec("req-computing-core-sbom-vulns-9")
    def test_two_bom_refs_for_one_package_are_one_match(self):
        components = [
            _component(ref="a", purl="pkg:apk/wolfi/zlib@1.0?package-id=1"),
            _component(ref="b", purl="pkg:apk/wolfi/zlib@1.0?package-id=2"),
        ]
        batch = _read(_doc([_entry(ref="a"), _entry(ref="b")], components))
        assert len(batch.matches) == 1
        assert batch.report.duplicate_matches_collapsed == 1

    @pytest.mark.spec("req-computing-core-sbom-vulns-9")
    def test_an_unmatched_vulnerability_is_listed(self):
        batch = _read(_doc([_entry("CVE-2026-0002", ref="nope")]))
        assert batch.unmatched_vulnerabilities() == ("CVE-2026-0002",)

    @pytest.mark.spec("req-computing-core-sbom-vulns-9")
    def test_a_repeated_bom_ref_is_refused_because_the_affect_is_ambiguous(self):
        with pytest.raises(SbomParseError, match="names two components"):
            _read(
                _doc(
                    [_entry()],
                    [_component(), _component(purl="pkg:apk/wolfi/zlib@1.0?x=1", ref="pkg:apk/wolfi/zlib@1.0")],
                )
            )


class TestDeterministic:
    """req-computing-core-sbom-vulns-10."""

    @pytest.mark.spec("req-computing-core-sbom-vulns-10")
    def test_the_same_bytes_twice_are_the_same_batch(self, corpus_bytes, batch):
        assert parse_cyclonedx_vulnerabilities(corpus_bytes, verification=VERIFIED) == batch

    @pytest.mark.spec("req-computing-core-sbom-vulns-10")
    def test_reordered_entries_and_components_are_the_same_batch(self, corpus, batch):
        shuffled = copy.deepcopy(corpus)
        rng = random.Random(20261019)
        rng.shuffle(shuffled["vulnerabilities"])
        rng.shuffle(shuffled["components"])
        other = _read(json.dumps(shuffled).encode())
        assert other.vulnerabilities == batch.vulnerabilities
        assert other.matches == batch.matches
        assert other.detectors == batch.detectors
        assert other.report == batch.report
        assert other.document.content_digest != batch.document.content_digest


class TestUnreadableIsRefusedNotEmpty:
    """req-computing-core-sbom-vulns-11."""

    @pytest.mark.spec("req-computing-core-sbom-vulns-11")
    @pytest.mark.parametrize(
        "body", [b"", b"   ", b"not json", b"[]", b'{"bomFormat": "SPDX"}', b'{"spdxVersion": "SPDX-2.3"}']
    )
    def test_unreadable_bodies_raise(self, body):
        with pytest.raises(SbomParseError):
            _read(body)

    @pytest.mark.spec("req-computing-core-sbom-vulns-11")
    def test_a_body_over_the_size_cap_raises(self):
        with pytest.raises(SbomParseError, match="size cap"):
            _read(b" " * (8 * 1024 * 1024 + 1))

    @pytest.mark.spec("req-computing-core-sbom-vulns-11")
    def test_more_entries_than_the_cap_raises(self, monkeypatch):
        monkeypatch.setattr(vulns_module, "MAX_VULNERABILITIES", 2)
        with pytest.raises(SbomParseError, match="over the cap"):
            _read(_doc([_entry(), _entry(), _entry()]))

    @pytest.mark.spec("req-computing-core-sbom-vulns-11")
    def test_a_document_with_no_components_is_refused(self):
        with pytest.raises(SbomParseError, match="no components"):
            _read(_doc([], []))


class TestDigestOverTheExactBytes:
    """req-computing-core-sbom-vulns-12."""

    @pytest.mark.spec("req-computing-core-sbom-vulns-12")
    def test_the_digest_is_over_the_bytes_and_matches_the_sbom_document_row(self, corpus_bytes, batch):
        assert batch.document.content_digest == hashlib.sha256(corpus_bytes).hexdigest()
        parsed = parse_cyclonedx(corpus_bytes, host_id=HOST, verification=VERIFIED)
        (row,) = parsed.nodes_of("computing_core__sbom_document")
        assert row.properties["content_digest"] == batch.document.content_digest
        assert row.properties["serial_number"] == batch.document.serial_number
        assert row.properties["revision"] == batch.document.revision == 2


class TestEntriesOfOneIdArePooled:
    """req-computing-core-sbom-vulns-13. Synthetic: the real document's entries agree."""

    @pytest.mark.spec("req-computing-core-sbom-vulns-13")
    def test_disagreement_is_named_and_the_listing_wins(self):
        components = [_component("a", "1"), _component("b", "1")]
        first = _entry(
            ref="pkg:apk/wolfi/a@1", description="one", properties=[{"name": "tap:kev:listed", "value": "false"}]
        )
        second = _entry(
            ref="pkg:apk/wolfi/b@1", description="two", properties=[{"name": "tap:kev:listed", "value": "true"}]
        )
        batch = _read(_doc([second, first], components))
        (record,) = batch.vulnerabilities
        assert record.description == "one"  # first in ref order, whatever the document order
        assert record.kev.listed is True
        assert any("disagree on the description" in n for n in batch.report.notes)
        assert any("disagree on the KEV listing" in n for n in batch.report.notes)
        assert len(batch.matches) == 2

    @pytest.mark.spec("req-computing-core-sbom-vulns-13")
    def test_ratings_are_pooled_across_entries(self):
        components = [_component("a", "1"), _component("b", "1")]
        low = {"source": {"name": "x"}, "method": "CVSSv31", "score": 4.0}
        high = {"source": {"name": "y"}, "method": "CVSSv31", "score": 8.0}
        entries = [_entry(ref="pkg:apk/wolfi/a@1", ratings=[low]), _entry(ref="pkg:apk/wolfi/b@1", ratings=[high])]
        assert _read(_doc(entries, components)).vulnerabilities[0].cvss.score == 8.0


class TestAVexStatementIsCarried:
    """req-computing-core-sbom-vulns-14. Synthetic: the CI workflow writes no `analysis` today."""

    @pytest.mark.spec("req-computing-core-sbom-vulns-14")
    @pytest.mark.parametrize("state", ["not_affected", "false_positive", "resolved", "resolved_with_pedigree"])
    def test_a_not_exposed_state_is_not_exposed(self, state):
        (match,) = _read(_doc([_entry(analysis={"state": state})])).matches
        assert (match.analysis_state, match.exposed) == (state, False)

    @pytest.mark.spec("req-computing-core-sbom-vulns-14")
    @pytest.mark.parametrize("analysis", [{"state": "exploitable"}, {"state": "in_triage"}, {}, None])
    def test_any_other_state_or_none_is_exposed(self, analysis):
        extra = {} if analysis is None else {"analysis": analysis}
        (match,) = _read(_doc([_entry(**extra)])).matches
        assert match.exposed is True


class TestTitlePublicationAndRecordLink:
    """req-computing-core-sbom-vulns-15, over the real revision 3 (signed by sbom-vulnerability-evidence.yml@e9841198)."""

    @pytest.fixture(scope="class")
    def rev3(self) -> VulnerabilityBatch:
        return _read(REV3.read_bytes())

    @pytest.mark.spec("req-computing-core-sbom-vulns-15")
    def test_the_counts_and_the_lineage(self, rev3):
        assert (len(rev3.vulnerabilities), len(rev3.matches)) == (27, 94)
        assert rev3.document.revision == 3
        assert rev3.document.previous_content_digest.startswith("sha256:d65c0620")

    @pytest.mark.spec("req-computing-core-sbom-vulns-15")
    def test_every_record_has_a_title_a_publication_time_and_a_record_link(self, rev3):
        for record in rev3.vulnerabilities:
            assert record.title, record.vuln_id
            assert record.published_at, record.vuln_id
            assert record.record_url, record.vuln_id
            assert record.record_updated_at, record.vuln_id
            assert record.description, record.vuln_id

    @pytest.mark.spec("req-computing-core-sbom-vulns-15")
    def test_a_cve_links_its_cve_record_and_a_ghsa_only_id_its_advisory(self, rev3):
        cve = _record(rev3, "CVE-2025-15367")
        assert cve.title == "POP3 command injection in user-controlled commands"
        assert cve.published_at == "2026-01-20T21:47:09.885Z"
        assert cve.record_url == "https://www.cve.org/CVERecord?id=CVE-2025-15367"
        ghsa = _record(rev3, "GHSA-fmf4-pr35-46c2")
        assert ghsa.published_at == "2026-09-22T18:33:29Z"
        assert ghsa.record_url == "https://github.com/advisories/GHSA-fmf4-pr35-46c2"
        assert [a.title for a in ghsa.advisories] == ["GitHub Advisory"]

    @pytest.mark.spec("req-computing-core-sbom-vulns-15")
    def test_both_links_are_kept_when_an_entry_gives_both(self, rev3):
        both = [r for r in rev3.vulnerabilities if len(r.advisories) == 2]
        assert both
        assert all(r.record_url.startswith("https://www.cve.org/") for r in both)

    @pytest.mark.spec("req-computing-core-sbom-vulns-15")
    def test_a_publication_time_that_is_not_a_date_time_is_none_with_a_note(self):
        batch = _read(_doc([_entry(published="last Tuesday")]))
        assert batch.vulnerabilities[0].published_at is None
        assert any("publication time" in n for n in batch.report.notes)
