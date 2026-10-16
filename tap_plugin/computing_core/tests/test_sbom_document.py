"""Tests for `sbom_document`, the record that one SBOM existed (req-computing-core-sbom-document).

Creation through the service layer, the content-digest key, revision lineage, the three-state
`verified`, the `DESCRIBES_HOST` edge, and that no column holds the document body.
"""

import json
import uuid
from pathlib import Path

import pytest
import tap_plugin.computing_core.models as computing  # noqa: F401 — trigger model registration

from tap_grid.constraints import InvalidEdgeError
from tap_grid.grift import grift_import
from tap_grid.models import Entity
from tap_grid.registry import get_model_class
from tap_grid.services import create_edge, create_node

TYPE = "computing_core__sbom_document"
DIGEST = "734809b9e5439845a25776385f36e50874789d7069e8231fe9ad80990d417aba"
SERIAL = "urn:uuid:90f083a0-a7b6-4183-a41d-ad1bb111feeb"
SUBJECT = "sha256:a9149a88a6239fc7a5351d9854fbff42448d2ed28cc71951a4c2aa2f4aca7750"
DOCUMENT = {
    "content_digest": DIGEST,
    "format": "cyclonedx",
    "spec_version": "1.7",
    "serial_number": SERIAL,
    "revision": 1,
    "subject_digest": SUBJECT,
    "produced_at": "2026-10-15T15:02:05Z",
    "generator": "syft@1.51.0",
    "component_count": 192,
}
HOST = {"realm": "assert", "stable_id": "tap-web-image", "kind": "container"}
EDGE = Path(__file__).resolve().parents[1] / "edges" / "DESCRIBES_HOST.edge.json"


def _import_document(properties: dict) -> object:
    """Import one `sbom_document` named by a batch-local ref, the way a parser's batch arrives."""
    envelope = {
        "metadata": {"grift_version": "0"},
        "_reserved": {},
        "batches": [
            {
                "batch_entity": {
                    "entity_id": str(uuid.uuid4()),
                    "entity_type": "batch",
                    "name": "sbom document test",
                    "dimensions": {},
                },
                "batch_node": {"name": "sbom document test", "description": "", "source": "test", "metadata": {}},
                "nodes": [
                    {
                        "entity": {
                            "ref": "doc",
                            "entity_type": TYPE,
                            "name": "sbom",
                            "dimensions": {"tap.computing": "runtime"},
                        },
                        "node": properties,
                    }
                ],
                "edges": [],
            }
        ],
    }
    result = grift_import(envelope)
    assert result.success, result.errors
    return result


def _create(type_slug: str, payload: dict):
    result = create_node(type_slug, payload)
    assert result.success, f"create_node failed: {result.errors}"
    return get_model_class(type_slug).objects.get(entity=Entity.objects.get(pk=result.entity_id))


@pytest.mark.django_db
class TestKeyedByContentDigest:
    """req-computing-core-sbom-document-1."""

    def test_declares_the_digest_as_its_natural_key(self):
        assert get_model_class(TYPE).NATURAL_KEY == ("content_digest",)

    def test_create_and_display(self):
        node = _create(TYPE, DOCUMENT)
        node.entity.refresh_from_db()
        assert node.entity.name == "sbom 734809b9e543 r1"
        assert node.entity.dimensions.get("tap.computing") == "runtime"

    def test_found_again_by_digest(self):
        node = _create(TYPE, DOCUMENT)
        model = get_model_class(TYPE)
        assert model.find_existing(content_digest=DIGEST).pk == node.pk
        assert model.find_existing(content_digest="0" * 64) is None

    def test_the_digest_is_required(self):
        payload = {k: v for k, v in DOCUMENT.items() if k != "content_digest"}
        assert not create_node(TYPE, payload).success

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "abc",
            DIGEST.upper(),  # upper-case hex
            DIGEST[:-1],  # 63 characters
            DIGEST + "0",  # 65 characters
            "sha256:" + DIGEST,  # the algorithm prefix is not part of the key
            "g" * 64,
        ],
    )
    def test_anything_but_64_lowercase_hex_is_refused(self, bad):
        assert not create_node(TYPE, {**DOCUMENT, "content_digest": bad}).success


@pytest.mark.django_db
class TestRevisionsAccumulate:
    """req-computing-core-sbom-document-2."""

    def test_the_same_bytes_imported_twice_are_one_node(self):
        first = _import_document(DOCUMENT).imported_batches[0].resolved_refs["doc"]
        second = _import_document(DOCUMENT).imported_batches[0].resolved_refs["doc"]
        assert first == second
        assert get_model_class(TYPE).objects.filter(content_digest=DIGEST).count() == 1

    def test_a_different_digest_imported_after_it_is_a_second_node(self):
        _import_document(DOCUMENT)
        _import_document({**DOCUMENT, "content_digest": "cd" * 32, "revision": 2})
        assert get_model_class(TYPE).objects.filter(subject_digest=SUBJECT).count() == 2

    def test_a_higher_revision_of_one_lineage_is_a_second_node_and_the_first_stays(self):
        first = _create(TYPE, DOCUMENT)
        second = _create(TYPE, {**DOCUMENT, "content_digest": "cd" * 32, "revision": 2})
        assert first.pk != second.pk
        model = get_model_class(TYPE)
        lineage = model.objects.filter(subject_digest=SUBJECT, serial_number=SERIAL).order_by("revision")
        assert [n.revision for n in lineage] == [1, 2]
        first.entity.refresh_from_db()
        assert first.entity.deleted_at is None

    def test_two_byte_strings_claiming_one_serial_and_revision_are_two_nodes(self):
        """The grid records the clash and does not pick between them."""
        one = _create(TYPE, DOCUMENT)
        other = _create(TYPE, {**DOCUMENT, "content_digest": "ef" * 32})
        assert one.pk != other.pk
        assert (one.serial_number, one.revision) == (other.serial_number, other.revision)

    @pytest.mark.parametrize("bad", [0, -1, 1.5, "1"])
    def test_revision_counts_from_one(self, bad):
        assert not create_node(TYPE, {**DOCUMENT, "revision": bad}).success


@pytest.mark.django_db
class TestVerifiedIsThreeState:
    """req-computing-core-sbom-document-3."""

    def test_not_checked_is_the_default_and_means_null(self):
        node = _create(TYPE, DOCUMENT)
        node.refresh_from_db()
        assert node.verified is None
        assert node.signer == ""

    @pytest.mark.parametrize("state", [True, False, None])
    def test_true_false_and_null_are_accepted(self, state):
        extra = {False: {"verification_note": "signer-identity"}, True: {"signer": "ci"}, None: {}}[state]
        node = _create(TYPE, {**DOCUMENT, "verified": state, **extra})
        node.refresh_from_db()
        assert node.verified is state

    @pytest.mark.parametrize("bad", ["true", 1, 0, "unknown"])
    def test_anything_else_is_refused(self, bad):
        assert not create_node(TYPE, {**DOCUMENT, "verified": bad}).success

    def test_a_signer_needs_verified_true(self):
        assert _create(TYPE, {**DOCUMENT, "verified": True, "signer": "ci@example.org"}).signer == "ci@example.org"
        assert not create_node(TYPE, {**DOCUMENT, "verified": False, "signer": "ci@example.org"}).success
        assert not create_node(TYPE, {**DOCUMENT, "verified": None, "signer": "ci@example.org"}).success
        assert not create_node(TYPE, {**DOCUMENT, "signer": "ci@example.org"}).success


@pytest.mark.django_db
class TestDescribesHost:
    """req-computing-core-sbom-document-4."""

    def test_connects_a_document_to_a_host(self):
        edge = create_edge(
            _create(TYPE, DOCUMENT).entity,
            _create("computing_core__host", HOST).entity,
            "DESCRIBES_HOST__computing_core",
        )
        assert edge.entity.dimensions.get("tap.computing") == "runtime"

    @pytest.mark.parametrize(
        ("src", "dst"),
        [("host", "sbom"), ("sbom", "package"), ("sbom", "sbom"), ("package", "host"), ("sbom", "os")],
    )
    def test_the_reverse_and_other_endpoint_types_are_refused(self, src, dst):
        nodes = {
            "sbom": _create(TYPE, DOCUMENT),
            "host": _create("computing_core__host", HOST),
            "package": _create("computing_core__package", {"ecosystem": "apk", "name": "zlib", "version": "1"}),
            "os": _create("computing_core__operating_system", {"os_id": "wolfi", "version_id": "1", "build_id": ""}),
        }
        with pytest.raises(InvalidEdgeError):
            create_edge(nodes[src].entity, nodes[dst].entity, "DESCRIBES_HOST__computing_core")

    def test_nothing_may_point_at_a_document(self):
        """`INBOUND_EDGES = []` is what closes the target side: a wildcard edge from an open type is refused.

        `GENERATES_FILE` accepts any source and any target and `program` declares no edges, so the
        only thing that can refuse program -> sbom_document is the document's own empty declaration.
        """
        program = _create("computing_core__program", {"program_name": "syft"})
        with pytest.raises(InvalidEdgeError):
            create_edge(program.entity, _create(TYPE, DOCUMENT).entity, "GENERATES_FILE__computing_core")

    def test_declares_the_plain_identity_and_no_properties(self):
        definition = json.loads(EDGE.read_text())
        assert definition["identity"] == {"discriminators": []}
        assert "property_schema" not in definition
        assert definition["default_dimensions"] == {"tap.computing": "runtime"}

    def test_is_not_containment(self):
        assert "DESCRIBES_HOST__computing_core" not in get_model_class("computing_core__host").CONTAINMENT_EDGES
        assert "DESCRIBES_HOST__computing_core" not in get_model_class(TYPE).CONTAINMENT_EDGES


@pytest.mark.django_db
class TestNoDocumentBody:
    """req-computing-core-sbom-document-5. Sits beside req-computing-core-models-7."""

    def test_no_column_holds_the_document_or_its_components(self):
        fields = {f.name for f in get_model_class(TYPE)._meta.concrete_fields}
        assert {"content_digest", "component_count"} <= fields
        assert not fields & {"document", "body", "content", "components", "data", "raw", "json", "configuration"}

    @pytest.mark.parametrize("key", ["components", "document", "body", "bom", "configuration"])
    def test_a_create_carrying_one_is_refused(self, key):
        assert not create_node(TYPE, {**DOCUMENT, key: {"anything": 1}}).success


@pytest.mark.django_db
class TestValuesFitTheColumns:
    """A value the column cannot hold, or a timestamp a reader would misread, is refused at the model."""

    @pytest.mark.parametrize(
        ("field", "bad"),
        [
            ("produced_at", "20261015"),
            ("produced_at", "2026-10-15"),
            ("produced_at", "2026-10-15T15:02:05"),  # no zone
            ("produced_at", 20261015),
            ("subject_digest", "sha256:" + "a" * 129),
            ("subject_digest", "sha256:"),
            ("subject_digest", "x" * 32 + ":" + "a" * 8),
            ("generator", "g" * 256),
            ("spec_version", "1" * 17),
            ("revision", 2**31),
            ("component_count", 2**31),
            ("signer", "s" * 513),
        ],
    )
    def test_it_is_refused(self, field, bad):
        assert not create_node(TYPE, {**DOCUMENT, "verified": True, "signer": "ci", field: bad}).success

    @pytest.mark.parametrize("good", ["2026-10-15T15:02:05Z", "2026-10-15T15:02:05.123+02:00", None])
    def test_a_full_timestamp_or_null_is_accepted(self, good):
        assert create_node(TYPE, {**DOCUMENT, "produced_at": good}).success

    def test_the_widest_values_that_fit_are_accepted(self):
        widest = {
            **DOCUMENT,
            "subject_digest": "a" * 31 + ":" + "b" * 128,
            "generator": "g" * 255,
            "spec_version": "1" * 16,
            "revision": 2**31 - 1,
            "component_count": 2**31 - 1,
        }
        assert create_node(TYPE, widest).success

    def test_a_loaded_row_still_validates_after_its_timestamp_became_a_datetime(self):
        node = _create(TYPE, DOCUMENT)
        node.refresh_from_db()
        node.full_validate()


@pytest.mark.django_db
class TestARefusedDocumentNamesItsCheck:
    """req-computing-core-sbom-document-6: the tri-state outcome is recorded on the node, never dropped."""

    @pytest.mark.parametrize("check", ["signer-identity", "subject-digest", "predicate-type"])
    def test_a_refused_document_is_stored_with_the_check_that_failed(self, check):
        node = _create(TYPE, {**DOCUMENT, "verified": False, "verification_note": check})
        node.refresh_from_db()
        assert (node.verified, node.verification_note, node.signer) == (False, check, "")

    def test_a_refused_document_without_a_check_is_refused(self):
        assert not create_node(TYPE, {**DOCUMENT, "verified": False}).success
        assert not create_node(TYPE, {**DOCUMENT, "verified": False, "verification_note": ""}).success

    def test_a_verified_document_has_no_note(self):
        assert not create_node(
            TYPE, {**DOCUMENT, "verified": True, "signer": "ci@example.org", "verification_note": "x"}
        ).success
        assert create_node(TYPE, {**DOCUMENT, "verified": True, "signer": "ci@example.org"}).success

    def test_a_document_that_could_not_be_checked_may_say_why_or_not(self):
        assert create_node(TYPE, {**DOCUMENT, "verified": None}).success
        assert create_node(
            TYPE, {**DOCUMENT, "content_digest": "cd" * 32, "verified": None, "verification_note": "no attestation"}
        ).success

    def test_the_note_is_bounded_to_its_column(self):
        assert create_node(TYPE, {**DOCUMENT, "verified": False, "verification_note": "n" * 255}).success
        assert not create_node(
            TYPE, {**DOCUMENT, "content_digest": "cd" * 32, "verified": False, "verification_note": "n" * 256}
        ).success


@pytest.mark.django_db
class TestCurrentIsVerifiedOnly:
    """req-computing-core-sbom-document-7: a refused or unchecked document never supersedes a verified one."""

    def _doc(self, n: int, revision: int, **fields):
        return _create(TYPE, {**DOCUMENT, "content_digest": f"{n:02x}" * 32, "revision": revision, **fields})

    def test_the_highest_verified_revision_is_current(self):
        self._doc(1, 1, verified=True, signer="ci")
        two = self._doc(2, 2, verified=True, signer="ci")
        assert get_model_class(TYPE).current(SUBJECT, SERIAL).pk == two.pk

    def test_a_higher_revision_that_was_refused_or_unchecked_is_not_current(self):
        one = self._doc(1, 1, verified=True, signer="ci")
        self._doc(2, 2, verified=False, verification_note="signer-identity")
        self._doc(3, 3, verified=None)
        assert get_model_class(TYPE).current(SUBJECT, SERIAL).pk == one.pk

    def test_a_lineage_with_no_verified_document_has_no_current(self):
        self._doc(1, 1, verified=False, verification_note="subject-digest")
        self._doc(2, 2, verified=None)
        assert get_model_class(TYPE).current(SUBJECT, SERIAL) is None

    def test_another_lineage_is_not_mixed_in(self):
        self._doc(1, 1, verified=True, signer="ci")
        assert get_model_class(TYPE).current(SUBJECT, "urn:uuid:11111111-2222-3333-4444-555555555555") is None


@pytest.mark.django_db
class TestStrictShapes:
    """The patterns end at the end of the string, not before a trailing newline; a verified document names its signer."""

    def test_a_verified_document_must_name_its_signer(self):
        assert not create_node(TYPE, {**DOCUMENT, "verified": True}).success
        assert not create_node(TYPE, {**DOCUMENT, "verified": True, "signer": ""}).success
        assert create_node(TYPE, {**DOCUMENT, "verified": True, "signer": "ci@example.org"}).success

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("content_digest", DIGEST + "\n"),
            ("subject_digest", SUBJECT + "\n"),
            ("serial_number", SERIAL + "\n"),
            ("produced_at", "2026-10-15T15:02:05Z\n"),
            ("format", "cyclonedx\n"),
        ],
    )
    def test_a_trailing_newline_is_refused(self, field, value):
        assert not create_node(TYPE, {**DOCUMENT, field: value}).success

    @pytest.mark.parametrize("value", ["a\nb", "a\tb", "a\x00b", "a\x7fb", "trailing\n"])
    def test_no_control_character_in_a_signer_or_a_note(self, value):
        assert not create_node(TYPE, {**DOCUMENT, "verified": True, "signer": value}).success
        assert not create_node(TYPE, {**DOCUMENT, "verified": False, "verification_note": value}).success


class TestProducedAtValidatorIsWired:
    """`{"validation": "function"}` resolves to `validate_produced_at` on the real `full_validate()` path."""

    def _row(self, **fields):
        return get_model_class(TYPE)(content_digest=DIGEST, **fields)

    @pytest.mark.parametrize(
        "bad", ["20261015", "2026-10-15", "2026-10-15T15:02:05", 20261015, "2026-10-15T15:02:05Z\n"]
    )
    def test_full_validate_refuses_a_bad_timestamp_through_the_function_entry(self, bad):
        from django.core.exceptions import ValidationError

        assert get_model_class(TYPE).FIELD_VALIDATION_SCHEMA["produced_at"] == {"validation": "function"}
        with pytest.raises(ValidationError) as raised:
            self._row(produced_at=bad).full_validate()
        assert "produced_at" in raised.value.message_dict

    @pytest.mark.parametrize("good", [None, "2026-10-15T15:02:05Z"])
    def test_full_validate_accepts_null_and_a_full_timestamp(self, good):
        self._row(produced_at=good).full_validate()

    def test_full_validate_accepts_the_datetime_of_a_loaded_row(self):
        from datetime import UTC, datetime

        self._row(produced_at=datetime(2026, 10, 15, 15, 2, 5, tzinfo=UTC)).full_validate()
