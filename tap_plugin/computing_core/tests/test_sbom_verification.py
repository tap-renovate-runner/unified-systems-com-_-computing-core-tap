"""The verification outcome on the document row, and recording a document that was not parsed.

req-computing-core-sbom-parse-10 and -11, from req-cicd-sbom-22-2 and -22-9: only a verified
document is parsed; a refused or not-observable one is recorded on the SBOM node with its failing
check named, never dropped. No test here needs a database except the import at the end.
"""

import hashlib
import uuid
from pathlib import Path

import pytest
from tap_plugin.computing_core.sbom import Verification, parse_cyclonedx, record_document
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
            (("verified", "signer-identity", "ci"), "no failing check"),
            (("refused", "x", "ci@example.org"), "only a verified"),
            (("not-observable", "", "ci@example.org"), "only a verified"),
            (("refused", "c" * 256), "at most 255"),
            (("verified", "", "s" * 513), "at most 255 characters and signer at most 512"),
            (("verified",), "names its signer"),
            (("verified", "", "   "), "names its signer"),
            (("refused", "signer-identity\nforged log line"), "no control character"),
            (("refused", "a\tb"), "no control character"),
            (("verified", "", "ci\n@example.org"), "no control character"),
            (("refused", "x\x00"), "no control character"),
        ],
    )
    def test_a_contradictory_or_oversize_outcome_is_refused(self, args, why):
        with pytest.raises(ValueError, match=why):
            Verification(*args)


class TestOnlyAVerifiedDocumentIsParsed:
    """req-computing-core-sbom-parse-10: parse_cyclonedx has no default; unverified is never parsed."""

    @pytest.mark.parametrize("verification", [REFUSED, UNCHECKED])
    def test_a_refused_or_unchecked_document_is_not_parsed(self, corpus_bytes, verification):
        with pytest.raises(ValueError, match="is not parsed; use record_document"):
            parse_cyclonedx(corpus_bytes, host_id=HOST, verification=verification)

    def test_omitting_verification_is_a_type_error_not_a_default(self, corpus_bytes):
        with pytest.raises(TypeError, match="verification"):
            parse_cyclonedx(corpus_bytes, host_id=HOST)  # type: ignore[call-arg]

    @pytest.mark.parametrize("not_a_verification", [None, "verified", True, {"outcome": "verified"}])
    def test_anything_that_is_not_a_verification_is_refused_before_a_byte_is_read(
        self, not_a_verification, monkeypatch
    ):
        import tap_plugin.computing_core.sbom.parser as parser

        monkeypatch.setattr(parser, "_load", lambda data: pytest.fail("the body was read"))
        with pytest.raises(ValueError, match="must be a Verification"):
            parse_cyclonedx(b"{}", host_id=HOST, verification=not_a_verification)  # type: ignore[arg-type]

    def test_a_refused_document_is_not_read_at_all(self, corpus_bytes, monkeypatch):
        import tap_plugin.computing_core.sbom.parser as parser

        monkeypatch.setattr(parser, "_load", lambda data: pytest.fail("the body was read"))
        with pytest.raises(ValueError):
            parse_cyclonedx(corpus_bytes, host_id=HOST, verification=REFUSED)

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

    def test_record_document_refuses_a_verified_one(self, corpus_bytes):
        with pytest.raises(ValueError, match="parsed with parse_cyclonedx"):
            record_document(corpus_bytes, verification=Verification("verified", signer="ci@example.org"))


class TestARefusedDocumentIsStillRecorded:
    """req-computing-core-sbom-parse-11: metadata only; nothing from the body is read."""

    EMPTY_ROW = {
        "format": "unknown",
        "spec_version": "",
        "serial_number": "",
        "revision": 1,
        "produced_at": None,
        "generator": "",
        "component_count": 0,
    }

    @pytest.mark.parametrize("verification", [REFUSED, UNCHECKED])
    def test_the_batch_carries_the_document_row_and_nothing_else(self, corpus_bytes, verification):
        batch = record_document(corpus_bytes, verification=verification, subject_digest=SUBJECT)
        assert [n.entity_type for n in batch.nodes] == [DOCUMENT]
        assert batch.edges == ()
        assert batch.nodes_of("computing_core__package") == ()

    def test_the_row_is_the_digest_the_outcome_the_check_and_the_callers_subject(self, corpus_bytes):
        (row,) = record_document(corpus_bytes, verification=REFUSED, subject_digest=SUBJECT).nodes
        assert row.properties == {
            **self.EMPTY_ROW,
            "content_digest": hashlib.sha256(corpus_bytes).hexdigest(),
            "subject_digest": SUBJECT,
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

    def test_the_body_is_never_json_parsed(self, corpus_bytes, monkeypatch):
        import json as json_module

        def boom(*args, **kwargs):
            raise AssertionError("record_document parsed the body")

        monkeypatch.setattr(json_module, "loads", boom)
        monkeypatch.setattr(json_module, "load", boom)
        assert record_document(corpus_bytes, verification=REFUSED).nodes

    @pytest.mark.parametrize(
        "body",
        [
            b"",
            b"\xff\xfe",
            b"{",
            b"[1,2]",
            b"null",
            b'{"bomFormat": "SPDX"}',
            b"[" * 200_000 + b"]" * 200_000,
            b'{"bomFormat": "CycloneDX", "specVersion": "1.7", "serialNumber": "urn:uuid:90f083a0-a7b6-4183-a41d-ad1bb111feeb", "version": 9}',
            b'{"bomFormat": "CycloneDX", "specVersion": ["1.6"], "version": 2}',
            b'{"bomFormat": "CycloneDX", "specVersion": {"a": 1}}',
        ],
    )
    def test_a_readable_and_an_unreadable_body_give_the_same_row_apart_from_the_digest(self, body):
        (row,) = record_document(body, verification=REFUSED).nodes
        assert {k: v for k, v in row.properties.items() if k != "content_digest"} == {
            **self.EMPTY_ROW,
            "subject_digest": "",
            "verified": False,
            "signer": "",
            "verification_note": "subject-digest",
        }
        assert row.properties["content_digest"] == hashlib.sha256(body).hexdigest()

    def test_the_subject_digest_is_the_callers(self, corpus_bytes):
        (row,) = record_document(corpus_bytes, verification=REFUSED).nodes
        assert row.properties["subject_digest"] == ""
        for bad in ("not a digest", SUBJECT + "\n", "sha256:" + "a" * 129, 5):
            with pytest.raises(ValueError, match="subject_digest"):
                record_document(corpus_bytes, verification=REFUSED, subject_digest=bad)

    @pytest.mark.parametrize("not_bytes", ["{}", 5, None, memoryview(b"{}"), ["a"], 1.5])
    def test_a_body_that_is_not_bytes_is_a_type_error_and_is_never_hashed(self, not_bytes):
        with pytest.raises(TypeError, match="must be bytes"):
            record_document(not_bytes, verification=REFUSED)  # type: ignore[arg-type]

    def test_a_bytearray_is_hashed_as_its_bytes(self):
        (row,) = record_document(bytearray(b"abc"), verification=REFUSED).nodes
        assert row.properties["content_digest"] == hashlib.sha256(b"abc").hexdigest()

    def test_verification_must_be_a_verification(self, corpus_bytes):
        with pytest.raises(TypeError, match="Verification"):
            record_document(corpus_bytes, verification="refused")  # type: ignore[arg-type]

    def test_the_report_says_it_was_not_parsed(self, corpus_bytes):
        batch = record_document(corpus_bytes, verification=REFUSED)
        assert batch.report.notes == ("recorded without parsing: refused (subject-digest)",)
        assert batch.report.component_count == 0

    def test_the_same_bytes_give_the_same_row_and_ref_as_a_verified_parse(self, corpus_bytes):
        a = record_document(corpus_bytes, verification=REFUSED)
        assert a == record_document(corpus_bytes, verification=REFUSED)
        verified = parse_cyclonedx(corpus_bytes, host_id=HOST, verification=Verification("verified", signer="s"))
        assert a.nodes[0].ref == verified.nodes_of(DOCUMENT)[0].ref
