"""`RUNS_PACKAGE`, `USES_KEY` and an operating system running a program.

req-computing-core-program-package, -program-key and -runtime-edges-4. Everything goes through the service layer.
Where an endpoint type declares no edges (program, private_key, public_key, file) the grid leaves that side open,
so the refusals below are the pairs a closed side (package, host) rules out.
"""

import json
from pathlib import Path

import pytest
import tap_plugin.computing_core.models as computing  # noqa: F401 - trigger model registration

from tap_grid.constraints import InvalidEdgeError
from tap_grid.models import Edge, Entity
from tap_grid.services import create_edge, create_node, delete_node

EDGES = Path(__file__).resolve().parents[1] / "edges"
C = "computing_core__"
ROOT = {"ecosystem": "pypi", "name": "tap", "version": "0.25.0"}
DEP = {"ecosystem": "pypi", "name": "django", "version": "6.0.8"}
WOLFI = {"os_id": "wolfi", "version_id": "20230201", "build_id": "sha256:" + "a" * 64, "rolling": True}
HOST = {"realm": "assert", "stable_id": "tap-web-image", "kind": "container"}


def _node(type_slug: str, payload: dict) -> Entity:
    result = create_node(C + type_slug, payload)
    assert result.success, f"create_node failed: {result.errors}"
    return Entity.objects.get(pk=result.entity_id)


def _nodes() -> dict[str, Entity]:
    return {
        "program": _node("program", {"program_name": "tap-web"}),
        "other_program": _node("program", {"program_name": "gunicorn"}),
        "root": _node("package", ROOT),
        "dependency": _node("package", DEP),
        "private_key": _node("private_key", {}),
        "public_key": _node("public_key", {}),
        "file": _node("file", {"file_path": "/etc/ssl/tls.crt"}),
        "os": _node("operating_system", WOLFI),
        "host": _node("host", HOST),
    }


def _edge(src: Entity, name: str, dst: Entity) -> Edge:
    return create_edge(src, dst, f"{name}__computing_core")


@pytest.mark.django_db
class TestRunsPackage:
    @pytest.mark.spec("req-computing-core-program-package-1")
    def test_a_program_runs_its_root_package(self) -> None:
        n = _nodes()
        created = _edge(n["program"], "RUNS_PACKAGE", n["root"])
        assert created.entity.dimensions.get("tap.computing") == "runtime"

    @pytest.mark.spec("req-computing-core-program-package-1")
    @pytest.mark.parametrize(
        ("src", "dst"),
        [("root", "program"), ("host", "root"), ("dependency", "root")],
    )
    def test_the_wrong_way_round_or_wrong_type_is_refused(self, src: str, dst: str) -> None:
        n = _nodes()
        with pytest.raises(InvalidEdgeError):
            _edge(n[src], "RUNS_PACKAGE", n[dst])

    @pytest.mark.spec("req-computing-core-program-package-2")
    def test_plain_identity_no_properties_runtime(self) -> None:
        definition = json.loads((EDGES / "RUNS_PACKAGE.edge.json").read_text())
        assert definition["slug"] == "RUNS_PACKAGE__computing_core"
        assert definition["identity"] == {"discriminators": []}
        assert "property_schema" not in definition
        assert definition["default_dimensions"] == {"tap.computing": "runtime"}

    @pytest.mark.spec("req-computing-core-program-package-2")
    def test_it_is_not_containment_and_retiring_a_program_leaves_its_root(self) -> None:
        for model in (computing.Package, computing.Program):
            assert "RUNS_PACKAGE__computing_core" not in getattr(model, "CONTAINMENT_EDGES", ())
        n = _nodes()
        _edge(n["program"], "RUNS_PACKAGE", n["root"])
        assert delete_node(n["program"].pk, cascade="contained").success
        n["root"].refresh_from_db()
        assert n["root"].deleted_at is None

    @pytest.mark.spec("req-computing-core-program-package-3")
    def test_the_closure_is_a_walk_over_requires_package_not_more_edges(self) -> None:
        n = _nodes()
        _edge(n["program"], "RUNS_PACKAGE", n["root"])
        _edge(n["root"], "REQUIRES_PACKAGE", n["dependency"])
        assert Edge.objects.filter(edge_type="RUNS_PACKAGE__computing_core").count() == 1
        assert not Edge.objects.filter(
            edge_type="RUNS_PACKAGE__computing_core", to_entity_id=n["dependency"].pk
        ).exists()

    @pytest.mark.spec("req-computing-core-program-package-4")
    def test_several_roots_and_shared_roots_are_one_edge_per_pair(self) -> None:
        n = _nodes()
        _edge(n["program"], "RUNS_PACKAGE", n["root"])
        _edge(n["program"], "RUNS_PACKAGE", n["dependency"])  # a second root of the same program
        _edge(n["other_program"], "RUNS_PACKAGE", n["root"])  # the same package, another program
        assert Edge.objects.filter(edge_type="RUNS_PACKAGE__computing_core").count() == 3

    @pytest.mark.spec("req-computing-core-program-package-5")
    def test_registered_in_the_manifest_and_on_package_inbound(self) -> None:
        manifest = (EDGES.parent / "tap-plugin.toml").read_text()
        assert 'RUNS_PACKAGE__computing_core = "edges/RUNS_PACKAGE.edge.json"' in manifest
        inbound = {e["type"] for entry in computing.Package.INBOUND_EDGES for e in entry["edges"]}
        assert "RUNS_PACKAGE__computing_core" in inbound

    @pytest.mark.spec("req-computing-core-program-package-6")
    def test_the_parser_draws_none(self) -> None:
        source = "\n".join(p.read_text() for p in (EDGES.parent / "sbom").glob("*.py"))
        assert "RUNS_PACKAGE" not in source


@pytest.mark.django_db
class TestUsesKey:
    @pytest.mark.spec("req-computing-core-program-key-1")
    @pytest.mark.parametrize("target", ["private_key", "public_key", "file"])
    def test_a_program_uses_a_key_or_a_file(self, target: str) -> None:
        n = _nodes()
        created = _edge(n["program"], "USES_KEY", n[target])
        assert created.entity.dimensions.get("tap.computing") == "runtime"

    @pytest.mark.spec("req-computing-core-program-key-1")
    @pytest.mark.parametrize("src", ["private_key", "public_key", "file"])
    def test_it_is_open_at_both_ends_so_the_reverse_is_not_refused_by_the_grid(self, src: str) -> None:
        """Documents the permission union: none of the four types declares edges, so nothing closes either side.

        The spec's "the reverse is refused wherever an endpoint declares its edges" has nothing to refuse here;
        a producer keeps to program -> key.
        """
        n = _nodes()
        _edge(n[src], "USES_KEY", n["program"])

    @pytest.mark.spec("req-computing-core-program-key-1")
    @pytest.mark.parametrize(("src", "dst"), [("host", "private_key"), ("program", "root")])
    def test_a_closed_side_still_refuses(self, src: str, dst: str) -> None:
        n = _nodes()
        with pytest.raises(InvalidEdgeError):
            _edge(n[src], "USES_KEY", n[dst])

    @pytest.mark.spec("req-computing-core-program-key-2")
    def test_plain_identity_no_properties_runtime(self) -> None:
        definition = json.loads((EDGES / "USES_KEY.edge.json").read_text())
        assert definition["slug"] == "USES_KEY__computing_core"
        assert definition["identity"] == {"discriminators": []}
        assert "property_schema" not in definition
        assert definition["default_dimensions"] == {"tap.computing": "runtime"}
        assert definition["sources"] == ["computing_core__program"]
        assert set(definition["targets"]) == {"computing_core__private_key", "computing_core__public_key", "computing_core__file"}

    @pytest.mark.spec("req-computing-core-program-key-2")
    def test_retiring_a_program_leaves_its_key(self) -> None:
        n = _nodes()
        _edge(n["program"], "USES_KEY", n["private_key"])
        assert delete_node(n["program"].pk, cascade="contained").success
        n["private_key"].refresh_from_db()
        assert n["private_key"].deleted_at is None

    @pytest.mark.spec("req-computing-core-program-key-3")
    def test_registered_in_the_manifest(self) -> None:
        manifest = (EDGES.parent / "tap-plugin.toml").read_text()
        assert 'USES_KEY__computing_core = "edges/USES_KEY.edge.json"' in manifest
        assert (EDGES / "USES_KEY.edge.json").exists()


@pytest.mark.django_db
class TestOperatingSystemRunsProgram:
    @pytest.mark.spec("req-computing-core-runtime-edges-4")
    def test_an_operating_system_runs_a_program_without_any_new_declaration(self) -> None:
        """Tested first, as the spec asks: operating_system declares INBOUND_EDGES only, and the edge was accepted."""
        n = _nodes()
        assert not hasattr(computing.OperatingSystem, "OUTBOUND_EDGES"), "operating_system declares inbound edges only"
        created = _edge(n["os"], "RUNS_PROGRAM", n["program"])
        assert created.entity.dimensions.get("tap.computing") == "runtime"

    @pytest.mark.spec("req-computing-core-runtime-edges-4")
    def test_the_meaning_is_recorded_in_the_edge_description(self) -> None:
        text = json.loads((EDGES / "RUNS_PROGRAM.edge.json").read_text())["description"]
        assert "holds its own programs" in text and "inherit" in text

    @pytest.mark.spec("req-computing-core-runtime-edges-4")
    def test_a_host_is_still_not_a_valid_target(self) -> None:
        n = _nodes()
        with pytest.raises(InvalidEdgeError):
            _edge(n["os"], "RUNS_PROGRAM", n["host"])
