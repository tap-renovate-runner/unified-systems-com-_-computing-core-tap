"""The verification outcome on the document row, and recording a document that was not parsed.

req-computing-core-sbom-parse-10 and -11, from req-cicd-sbom-22-2 and -22-9: only a verified
document is parsed; a refused or not-observable one is recorded on the SBOM node with its failing
check named, never dropped. No test here needs a database except the import at the end.
"""

import hashlib
import json
import uuid
from pathlib import Path

import pytest
from tap_plugin.computing_core.sbom import SbomParseError, Verification, parse_cyclonedx, record_document
from tap_plugin.computing_core.sbom.verification import PREDICATE_TYPE, SIGNER_IDENTITY, SUBJECT_DIGEST

CORPUS = Path(__file__).resolve().parent / "corpus" / "tap-web-latest-arm64.cdx.json"
HOST = str(uuid.UUID("01a13c38-4f5e-735c-9cf2-1f159f4282b6"))
DOCUMENT = "computing_core__sbom_document"
SUBJECT = "sha256:a9149a88a6239fc7a5351d9854fbff42448d2ed28cc71951a4c2aa2f4aca7750"
REFUSED = Verification("refused", SUBJECT_DIGEST)
UNCHECKED = Verification("not-observable", "no attestation was published")


@pytest.fixture(scope="module")
def corpus_bytes() -> bytes:
    return CORPUS.read_bytes()


class TestTheOutcomeMapsToTheTriState:
    def test_verified_is_true_refused_is_false_not_observable_is_null(self):
        assert Verification("verified", signer="ci@example.org").verified is True
        assert Verification("refused", SIGNER_IDENTITY).verified is False
        assert Verification("not-observable").verified is None

    @pytest.mark.parametrize("check", [SIGNER_IDENTITY, SUBJECT_DIGEST, PREDICATE_TYPE])
    def test_a_refusal_names_the_failing_check_in_the_note(self, check):
        assert Verification("refused", check).document_fields() == {
            "verified": False,
            "signer": "",
            "verification_note": check,
        }

    @pytest.mark.parametrize(
        ("args", "why"),
        [
            (("maybe",), "not one of"),
            (("refused",), "names the check"),
            (("refused", "   "), "names the check"),
            (("verified", "signer-identity"), "no failing check"),
            (("refused", "x", "ci@example.org"), "only a verified"),
            (("not-observable", "", "ci@example.org"), "only a verified"),
            (("refused", "c" * 256), "at most 255"),
            (("verified", "", "s" * 513), "at most 255 characters and signer at most 512"),
        ],
    )
    def test_a_contradictory_or_oversize_outcome_is_refused(self, args, why):
        with pytest.raises(ValueError, match=why):
            Verification(*args)


class TestOnlyAVerifiedDocumentIsParsed:
    """req-computing-core-sbom-parse-10."""

    @pytest.mark.parametrize("verification", [REFUSED, UNCHECKED])
    def test_a_refused_or_unchecked_document_is_not_parsed(self, corpus_bytes, verification):
        with pytest.raises(ValueError, match="is not parsed; use record_document"):
            parse_cyclonedx(corpus_bytes, host_id=HOST, verification=verification)

    def test_a_verified_document_is_parsed_and_its_row_says_so(self, corpus_bytes):
        batch = parse_cyclonedx(
            corpus_bytes, host_id=HOST, verification=Verification("verified", signer="ci@example.org")
        )
        (row,) = batch.nodes_of(DOCUMENT)
        assert (row.properties["verified"], row.properties["signer"], row.properties["verification_note"]) == (
            True,
            "ci@example.org",
            "",
        )
        assert len(batch.nodes_of("computing_core__package")) == 180

    def test_with_no_verification_given_the_row_makes_no_claim(self, corpus_bytes):
        (row,) = parse_cyclonedx(corpus_bytes, host_id=HOST).nodes_of(DOCUMENT)
        assert "verified" not in row.properties

    def test_record_document_refuses_a_verified_one(self, corpus_bytes):
        with pytest.raises(ValueError, match="parsed with parse_cyclonedx"):
            record_document(corpus_bytes, verification=Verification("verified"))


class TestARefusedDocumentIsStillRecorded:
    """req-computing-core-sbom-parse-11."""

    @pytest.mark.parametrize("verification", [REFUSED, UNCHECKED])
    def test_the_batch_carries_the_document_row_and_nothing_else(self, corpus_bytes, verification):
        batch = record_document(corpus_bytes, verification=verification, subject_digest=SUBJECT)
        assert [n.entity_type for n in batch.nodes] == [DOCUMENT]
        assert batch.edges == ()
        assert batch.nodes_of("computing_core__package") == ()

    def test_the_row_has_the_digest_of_the_exact_bytes_and_the_outcome(self, corpus_bytes):
        (row,) = record_document(corpus_bytes, verification=REFUSED, subject_digest=SUBJECT).nodes
        assert row.properties == {
            "content_digest": hashlib.sha256(corpus_bytes).hexdigest(),
            "format": "cyclonedx",
            "spec_version": "1.7",
            "serial_number": "urn:uuid:90f083a0-a7b6-4183-a41d-ad1bb111feeb",
            "revision": 1,
            "subject_digest": SUBJECT,
            "produced_at": None,
            "generator": "",
            "component_count": 0,
            "verified": False,
            "signer": "",
            "verification_note": "subject-digest",
        }

    def test_not_observable_is_null_with_its_reason(self, corpus_bytes):
        (row,) = record_document(corpus_bytes, verification=UNCHECKED).nodes
        assert (row.properties["verified"], row.properties["verification_note"]) == (
            None,
            "no attestation was published",
        )

    def test_the_subject_digest_is_the_callers_not_the_bodys(self, corpus_bytes):
        (row,) = record_document(corpus_bytes, verification=REFUSED).nodes
        assert row.properties["subject_digest"] == ""
        with pytest.raises(ValueError, match="subject_digest"):
            record_document(corpus_bytes, verification=REFUSED, subject_digest="not a digest")

    @pytest.mark.parametrize(
        "body",
        [b"", b"\xff\xfe", b"{", b"[1,2]", b"null", b'{"bomFormat": "SPDX"}', b"[" * 200_000 + b"]" * 200_000],
    )
    def test_an_unreadable_body_is_recorded_with_the_identifying_fields_empty(self, body):
        (row,) = record_document(body, verification=REFUSED).nodes
        assert row.properties["format"] == "unknown"
        assert (row.properties["spec_version"], row.properties["serial_number"], row.properties["revision"]) == (
            "",
            "",
            1,
        )
        assert row.properties["content_digest"] == hashlib.sha256(body).hexdigest()

    def test_a_hostile_body_gives_nothing_but_the_digest_and_safe_identifiers(self):
        body = json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "9.9",
                "serialNumber": "not-a-uuid",
                "version": 2**40,
                "components": [{"name": "evil", "version": "1", "purl": "pkg:apk/x/evil@1"}],
                "metadata": {"component": {"version": "sha256:" + "a" * 64}},
            }
        ).encode()
        batch = record_document(body, verification=REFUSED)
        (row,) = batch.nodes
        assert (row.properties["spec_version"], row.properties["serial_number"], row.properties["revision"]) == (
            "",
            "",
            1,
        )
        assert row.properties["subject_digest"] == ""
        assert [n.entity_type for n in batch.nodes] == [DOCUMENT]

    def test_the_report_says_it_was_not_parsed(self, corpus_bytes):
        batch = record_document(corpus_bytes, verification=REFUSED)
        assert batch.report.notes == ("recorded without parsing: refused (subject-digest)",)
        assert batch.report.component_count == 0

    def test_the_same_bytes_give_the_same_row_whatever_the_outcome_shape(self, corpus_bytes):
        a = record_document(corpus_bytes, verification=REFUSED)
        b = record_document(corpus_bytes, verification=REFUSED)
        assert a == b
        assert a.nodes[0].ref == parse_cyclonedx(corpus_bytes, host_id=HOST).nodes_of(DOCUMENT)[0].ref

    def test_the_helper_never_calls_the_package_parser(self, corpus_bytes, monkeypatch):
        import tap_plugin.computing_core.sbom.verification as module

        def boom(*args, **kwargs):
            raise AssertionError("record_document parsed the contents")

        monkeypatch.setattr("tap_plugin.computing_core.sbom.parser.parse_cyclonedx", boom)
        assert not hasattr(module, "parse_cyclonedx")
        assert record_document(corpus_bytes, verification=REFUSED).nodes
        with pytest.raises(SbomParseError):
            from tap_plugin.computing_core.sbom.parser import _load

            _load(b"")
