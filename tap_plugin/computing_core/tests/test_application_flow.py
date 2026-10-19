"""The application flow node and the four edges that came with it (req-computing-core-application-flow-*, req-computing-core-runtime-edges-*)."""

import json
import tomllib
from pathlib import Path

import pytest
import tap_plugin.computing_core.models as computing  # noqa: F401 — trigger model registration

from tap_grid.constraints import InvalidEdgeError
from tap_grid.models import Edge, Entity
from tap_grid.natural_key import KEYLESS
from tap_grid.registry import get_model_class
from tap_grid.services import create_edge, create_node, delete_node

PLUGIN = Path(__file__).resolve().parents[1]
EDGES = PLUGIN / "edges"
TYPE = "computing_core__application_flow"

# George-approved 2026-10-19; verbatim (req-computing-core-application-flow-2).
REASON = (
    "An application flow is a conceptual aggregate of traffic between a source and a destination; "
    "no source system observes it, so it has no stable identifier to key on yet. "
    "A natural key will be declared when one is found."
)

COMPUTER = {"realm": "assert", "stable_id": "customer-a-computer", "kind": "workstation"}
IMAGE_HOST = {"realm": "assert", "stable_id": "git-serious-web-image", "kind": "container"}


def _create(type_slug: str, payload: dict):
    result = create_node(type_slug, payload)
    assert result.success, f"create_node failed: {result.errors}"
    return get_model_class(type_slug).objects.get(entity=Entity.objects.get(pk=result.entity_id))


def _definition(slug: str) -> dict:
    return json.loads((EDGES / f"{slug}.edge.json").read_text())


@pytest.mark.django_db
class TestApplicationFlow:
    def test_create_and_display(self):
        flow = _create(TYPE, {"name": "customers reach tap-web", "description": "HTTPS from a customer computer."})
        flow.entity.refresh_from_db()
        assert flow.entity.name == "customers reach tap-web"
        assert flow.entity.dimensions.get("tap.computing") == "network"
        assert str(flow) == "customers reach tap-web"

    def test_it_holds_a_name_and_a_description_and_nothing_else(self):
        model = get_model_class(TYPE)
        assert set(model.FIELD_CRUD_SCHEMA) == {"name", "description"}
        assert set(model.FIELD_VALIDATION_SCHEMA) == {"name", "description"}
        assert model.CREATE_REQUIRED == []
        assert not create_node(TYPE, {"name": "x", "protocol": "https"}).success
        assert _create(TYPE, {}).get_name() == "application flow"

    def test_it_is_keyless_with_the_approved_reason(self):
        model = get_model_class(TYPE)
        assert model.NATURAL_KEY is KEYLESS
        assert model.NATURAL_KEY_REASON == REASON

    def test_two_flows_of_one_name_are_two_nodes(self):
        first = _create(TYPE, {"name": "same"})
        second = _create(TYPE, {"name": "same"})
        assert first.entity_id != second.entity_id

    def test_it_has_an_icon_file_and_a_display(self):
        model = get_model_class(TYPE)
        svg = (PLUGIN / "static" / "computing_core" / "icons" / f"{model.ENTITY_ICON}.svg").read_text()
        assert 'viewBox="0 0 80 80"' in svg
        display = model.DEFAULT_DISPLAY["tap_viz"]
        assert display["shape"] == "ellipse"
        assert display["colors"] == {"fill": "#0B3D91", "border": "#0B3D91", "label": "#0B3D91"}
        # The icon is the circle: one solid disc filling the viewBox, nothing drawn outside it.
        assert '<circle cx="40" cy="40" r="40" fill="#0B3D91"/>' in svg
        assert "<rect" not in svg

    def test_the_manifest_registers_the_type_and_the_flow_edges(self):
        manifest = tomllib.loads((PLUGIN / "tap-plugin.toml").read_text())
        assert manifest["models"][TYPE] == "tap_plugin.computing_core.models.application_flow.ApplicationFlow"
        for slug in (
            "APPLICATION_FLOW_SOURCE",
            "APPLICATION_FLOW_DESTINATION",
            "RUNS_PROGRAM",
            "RUNS_IMAGE",
        ):
            assert manifest["edges"][f"{slug}__computing_core"] == f"edges/{slug}.edge.json"
            assert _definition(slug)["slug"] == f"{slug}__computing_core"


@pytest.mark.django_db
class TestEdges:
    def test_a_flow_joins_any_sender_to_any_receiver(self):
        sender = _create("computing_core__host", COMPUTER)
        receiver = _create("computing_core__program", {"program_name": "tap-web"})
        flow = _create(TYPE, {"name": "customers reach tap-web"})
        source = create_edge(sender.entity, flow.entity, "APPLICATION_FLOW_SOURCE__computing_core")
        destination = create_edge(flow.entity, receiver.entity, "APPLICATION_FLOW_DESTINATION__computing_core")
        assert source.entity.dimensions.get("tap.computing") == "network"
        assert destination.entity.dimensions.get("tap.computing") == "network"
        assert (
            Edge.objects.filter(edge_type="APPLICATION_FLOW_SOURCE__computing_core", from_entity=sender.entity).count()
            == 1
        )
        assert (
            Edge.objects.filter(
                edge_type="APPLICATION_FLOW_DESTINATION__computing_core", to_entity=receiver.entity
            ).count()
            == 1
        )

    def test_the_flow_edges_are_open_at_both_ends_plain_and_not_containment(self):
        for slug in ("APPLICATION_FLOW_SOURCE", "APPLICATION_FLOW_DESTINATION"):
            definition = _definition(slug)
            assert "sources" not in definition and "targets" not in definition, slug
            assert definition["identity"] == {"discriminators": []}, slug
            assert "property_schema" not in definition, slug
            assert definition["default_dimensions"] == {"tap.computing": "network"}, slug
            # George's names, deliberately not <ACTION>_<OBJECT>: the description says so.
            assert "NOT the <ACTION>_<OBJECT> form" in definition["description"], slug
        # References: a flow outlives neither end by cascade yet (req-computing-core-application-flow-6 is proposed).
        sender = _create("computing_core__host", COMPUTER)
        receiver = _create("computing_core__program", {"program_name": "tap-web"})
        flow = _create(TYPE, {"name": "f"})
        create_edge(sender.entity, flow.entity, "APPLICATION_FLOW_SOURCE__computing_core")
        create_edge(flow.entity, receiver.entity, "APPLICATION_FLOW_DESTINATION__computing_core")
        assert delete_node(sender.entity_id, cascade="contained").success
        flow.entity.refresh_from_db()
        receiver.entity.refresh_from_db()
        assert flow.entity.deleted_at is None
        assert receiver.entity.deleted_at is None

    def test_runs_program_and_runs_image_connect(self):
        container = _create("computing_core__host", {**COMPUTER, "stable_id": "web-a-container", "kind": "container"})
        gunicorn = _create("computing_core__program", {"program_name": "gunicorn"})
        web = _create("computing_core__program", {"program_name": "tap-web"})
        image = _create("computing_core__host", IMAGE_HOST)
        for source, edge, target in [
            (container, "RUNS_PROGRAM", gunicorn),  # container -> gunicorn
            (gunicorn, "RUNS_PROGRAM", web),  # gunicorn -> tap-web: one verb for both
            (container, "RUNS_IMAGE", image),
        ]:
            created = create_edge(source.entity, target.entity, f"{edge}__computing_core")
            assert created.entity.dimensions.get("tap.computing") == "runtime", edge

    def test_a_program_may_send_and_receive_a_flow_too(self):
        """Types that declare no edges (program) take the open edges unchanged."""
        sender = _create("computing_core__program", {"program_name": "gunicorn"})
        receiver = _create("computing_core__program", {"program_name": "tap-web"})
        flow = _create(TYPE, {"name": "gunicorn reaches tap-web"})
        create_edge(sender.entity, flow.entity, "APPLICATION_FLOW_SOURCE__computing_core")
        create_edge(flow.entity, receiver.entity, "APPLICATION_FLOW_DESTINATION__computing_core")

    def test_runs_program_to_a_host_is_refused(self):
        """The target type is enforced only where the target type declares its edges (host does).

        The edge definition's `targets` is a grant, not a restriction (Permission Union): a type
        that declares no edges, such as `program` or `tcp_connection`, stays open at its end.
        """
        source = _create("computing_core__host", {**COMPUTER, "stable_id": "web-a-container", "kind": "container"})
        host = _create("computing_core__host", IMAGE_HOST)
        with pytest.raises(InvalidEdgeError):
            create_edge(source.entity, host.entity, "RUNS_PROGRAM__computing_core")

    def test_runs_edges_are_open_at_the_source_plain_and_not_containment(self):
        for slug, target in (("RUNS_PROGRAM", "computing_core__program"), ("RUNS_IMAGE", "computing_core__host")):
            definition = _definition(slug)
            assert "sources" not in definition, slug
            assert definition["targets"] == [target], slug
            assert definition["identity"] == {"discriminators": []}, slug
            assert "property_schema" not in definition, slug
            assert definition["default_dimensions"] == {"tap.computing": "runtime"}, slug
        container = _create("computing_core__host", {**COMPUTER, "stable_id": "web-a-container", "kind": "container"})
        gunicorn = _create("computing_core__program", {"program_name": "gunicorn"})
        image = _create("computing_core__host", IMAGE_HOST)
        create_edge(container.entity, gunicorn.entity, "RUNS_PROGRAM__computing_core")
        create_edge(container.entity, image.entity, "RUNS_IMAGE__computing_core")
        assert delete_node(container.entity_id, cascade="contained").success
        for node in (gunicorn, image):
            node.entity.refresh_from_db()
            assert node.entity.deleted_at is None
