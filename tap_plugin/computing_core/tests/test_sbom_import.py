"""The parser's batch is loadable: it goes through the GRIFT importer exactly as a bundle does.

This is the one test file in the SBOM work that needs a database. It shows that the refs the pure
parser emits resolve against the grid's natural keys (`req-grid-import-grift-identity-3`), that
the host the caller supplied is addressed by its id, and that importing the same document again
adds nothing. It does not replace the parser tests, which need none of this.
"""

import uuid
from pathlib import Path

import pytest
import tap_plugin.computing_core.models as computing  # noqa: F401 — trigger model registration
from tap_plugin.computing_core.sbom import SbomBatch, parse_cyclonedx

from tap_grid.grift import grift_import
from tap_grid.models import Edge, Entity
from tap_grid.registry import get_model_class
from tap_grid.services import create_node

CORPUS = Path(__file__).resolve().parent / "corpus" / "tap-web-latest-arm64.cdx.json"

pytestmark = pytest.mark.django_db


def _host() -> str:
    result = create_node("computing_core__host", {"realm": "assert", "stable_id": "tap-web-image", "kind": "container"})
    assert result.success, result.errors
    return str(result.entity_id)


def _import(batch: SbomBatch):
    document = {
        "metadata": {"grift_version": "0"},
        "_reserved": {},
        "batches": [batch.as_grift_batch(str(uuid.uuid4()), name="sbom ingest test", source="test")],
    }
    result = grift_import(document)
    assert result.success, [e.message for e in result.errors[:5]]
    return result


def _count(entity_type: str) -> int:
    return get_model_class(entity_type).objects.count()


def _live_edges(edge_type: str) -> int:
    return Edge.objects.filter(edge_type=edge_type, entity__deleted_at__isnull=True).count()


class TestTheCorpusImports:
    def test_it_lands_the_inventory_on_the_grid(self):
        host = _host()
        _import(parse_cyclonedx(CORPUS.read_bytes(), host_id=host))
        assert _count("computing_core__package") == 180
        assert _count("computing_core__library") == 3
        assert _count("computing_core__source_package") == 72
        assert _count("computing_core__operating_system") == 1
        assert _count("computing_core__sbom_document") == 1
        assert _live_edges("REQUIRES_PACKAGE__computing_core") == 450
        assert _live_edges("INSTALLS_PACKAGE__computing_core") == 180
        assert _live_edges("DERIVES_FROM_SOURCE_PACKAGE__computing_core") == 102
        assert _live_edges("RUNS_OPERATING_SYSTEM__computing_core") == 1
        assert _live_edges("DESCRIBES_HOST__computing_core") == 1

    def test_the_stored_packages_keep_the_whole_purl_and_the_candidates(self):
        host = _host()
        _import(parse_cyclonedx(CORPUS.read_bytes(), host_id=host))
        libssl3 = get_model_class("computing_core__package").objects.get(name="libssl3")
        assert libssl3.purl.endswith("?arch=aarch64&distro=wolfi-20230201&upstream=openssl")
        assert len(libssl3.cpe_candidates) == 3
        assert libssl3.architecture == "aarch64"

    def test_importing_the_same_document_again_adds_nothing(self):
        host = _host()
        batch = parse_cyclonedx(CORPUS.read_bytes(), host_id=host)
        _import(batch)
        entities, edges = Entity.objects.count(), Edge.objects.count()
        _import(batch)
        assert (Entity.objects.count() - 1, Edge.objects.count()) == (entities, edges)  # +1: the second batch entity

    def test_the_host_the_caller_named_is_the_one_the_edges_use(self):
        host = _host()
        _import(parse_cyclonedx(CORPUS.read_bytes(), host_id=host))
        installs = Edge.objects.filter(edge_type="INSTALLS_PACKAGE__computing_core")
        assert {str(e.from_entity_id) for e in installs} == {host}
