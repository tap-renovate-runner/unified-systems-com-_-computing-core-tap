"""The `module` node and its three edges (req-computing-core-module-*, req-computing-core-module-edges-*)."""

import json
import re
import tomllib
from pathlib import Path

import pytest
import tap_plugin.computing_core.models as computing  # noqa: F401 — trigger model registration

from tap_grid.constraints import InvalidEdgeError
from tap_grid.models import Entity
from tap_grid.registry import get_model_class
from tap_grid.services import create_edge, create_node, delete_node

PLUGIN = Path(__file__).resolve().parents[1]
EDGES = PLUGIN / "edges"
TYPE = "computing_core__module"
MODULE = {"scope": "tap", "name": "tap_grid", "language": "python", "path": "tap_grid", "source_file_count": 112}
PACKAGE = {"ecosystem": "pypi", "name": "tap", "version": "0.3.0"}
LIBRARY = {"ecosystem": "pypi", "name": "tap-grid", "version": "0.3.0", "language": "python"}
EDGE_SLUGS = ("LOADS_MODULE", "CONTAINS_MODULE", "IMPORTS_MODULE")


def _create(type_slug: str, payload: dict):
    result = create_node(type_slug, payload)
    assert result.success, f"create_node failed: {result.errors}"
    return get_model_class(type_slug).objects.get(entity=Entity.objects.get(pk=result.entity_id))


def _definition(slug: str) -> dict:
    return json.loads((EDGES / f"{slug}.edge.json").read_text())


@pytest.mark.django_db
class TestModule:
    def test_create_and_display(self):
        node = _create(TYPE, MODULE)
        node.entity.refresh_from_db()
        assert node.entity.name == "tap_grid"
        assert node.source_file_count == 112
        assert node.entity.dimensions.get("tap.computing") == "runtime"

    @pytest.mark.parametrize("missing", ["scope", "name", "language"])
    def test_required_fields(self, missing):
        """req-computing-core-module-1 and -2: scope and name are the key, language is required."""
        assert not create_node(TYPE, {k: v for k, v in MODULE.items() if k != missing}).success

    def test_keyed_by_scope_and_name(self):
        """req-computing-core-module-1: the same name in another scope is another node."""
        model = get_model_class(TYPE)
        assert model.NATURAL_KEY == ("scope", "name")
        node = _create(TYPE, MODULE)
        assert model.find_existing(scope="tap", name="tap_grid").pk == node.pk
        assert model.find_existing(scope="vuln_mosaic", name="tap_grid") is None
        assert _create(TYPE, {**MODULE, "scope": "vuln_mosaic"}).entity_id != node.entity_id

    @pytest.mark.parametrize("language", ["python", "go", "c", "c++", "c#", "javascript", "f#", "a" * 32])
    def test_language_shape_accepts(self, language):
        assert create_node(TYPE, {**MODULE, "language": language}).success

    @pytest.mark.parametrize("language", ["", "Python", "PYTHON", "1c", "-go", "a" * 33, "py thon", " go"])
    def test_language_shape_refuses(self, language):
        """req-computing-core-module-2: empty, upper case or too long is refused."""
        assert not create_node(TYPE, {**MODULE, "language": language}).success

    def test_counts_are_three_state(self):
        """req-computing-core-module-3: null stays null, 0 is a measured zero, negative is refused."""
        unmeasured = {k: v for k, v in MODULE.items() if k not in ("path", "source_file_count")}
        node = _create(TYPE, unmeasured)
        assert node.source_file_count is None
        assert node.path is None
        assert _create(TYPE, {**MODULE, "name": "empty", "source_file_count": 0}).source_file_count == 0
        assert _create(TYPE, {**MODULE, "name": "nulled", "source_file_count": None}).source_file_count is None

    @pytest.mark.parametrize("count", [-1, 1.5, "7", True])
    def test_a_bad_count_is_refused(self, count):
        assert not create_node(TYPE, {**MODULE, "source_file_count": count}).success

    @pytest.mark.parametrize("path", ["tap_grid", "tap_grid/gryphon.py", "src/a..b", "a/b/", ".hidden/x"])
    def test_a_relative_path_is_accepted(self, path):
        assert create_node(TYPE, {**MODULE, "path": path}).success

    @pytest.mark.parametrize(
        "path", ["/app/tap_grid", "../tap_grid", "a/../b", "a/..", "..", "C:\\src\\tap", "c:/src", "\\\\host\\share", ""]
    )
    def test_an_absolute_or_escaping_path_is_refused(self, path):
        """req-computing-core-module-4."""
        assert not create_node(TYPE, {**MODULE, "path": path}).success

    def test_it_has_no_field_that_could_hold_source_text(self):
        """req-computing-core-module-5: presence, never content."""
        model = get_model_class(TYPE)
        fields = {f.name for f in model._meta.concrete_fields}
        assert fields >= {"scope", "name", "language", "path", "source_file_count"}
        assert not {f for f in fields if any(w in f for w in ("source_text", "body", "content", "code", "secret"))}
        assert set(model.FIELD_CRUD_SCHEMA) == {"scope", "name", "language", "path", "source_file_count"}
        assert set(model.FIELD_VALIDATION_SCHEMA) == set(model.FIELD_CRUD_SCHEMA)
        assert not create_node(TYPE, {**MODULE, "source": "def f(): pass"}).success

    def test_registered_with_dimension_icon_and_display(self):
        """req-computing-core-module-6."""
        manifest = tomllib.loads((PLUGIN / "tap-plugin.toml").read_text())
        assert manifest["models"][TYPE] == "tap_plugin.computing_core.models.module.Module"
        model = get_model_class(TYPE)
        assert model.DEFAULT_DIMENSIONS == {"tap.computing": "runtime"}
        assert model.CREATE_REQUIRED == ["scope", "name", "language"]
        assert re.fullmatch(r"[a-z][a-z0-9+#.-]{0,31}", "python")
        svg = (PLUGIN / "static" / "computing_core" / "icons" / f"{model.ENTITY_ICON}.svg").read_text()
        assert 'viewBox="0 0 80 80"' in svg
        assert model.DEFAULT_DISPLAY["tap_viz"]["shape"] == "rectangle"


@pytest.mark.django_db
class TestModuleEdges:
    def _nodes(self):
        return {
            "program": _create("computing_core__program", {"program_name": "tap-web"}),
            "package": _create("computing_core__package", PACKAGE),
            "library": _create("computing_core__library", LIBRARY),
            "grid": _create(TYPE, MODULE),
            "gryphon": _create(TYPE, {**MODULE, "name": "tap_grid.gryphon", "path": "tap_grid/gryphon"}),
            "web": _create(TYPE, {**MODULE, "name": "tap_web", "path": "tap_web"}),
            "host": _create("computing_core__host", {"realm": "assert", "stable_id": "tap-web-image", "kind": "container"}),
        }

    def test_the_sentences_connect(self):
        """req-computing-core-module-edges-1."""
        n = self._nodes()
        for src, edge, dst in [
            ("program", "LOADS_MODULE", "grid"),
            ("package", "CONTAINS_MODULE", "grid"),
            ("library", "CONTAINS_MODULE", "gryphon"),
            ("grid", "CONTAINS_MODULE", "gryphon"),
            ("web", "IMPORTS_MODULE", "grid"),
        ]:
            created = create_edge(n[src].entity, n[dst].entity, f"{edge}__computing_core")
            assert created.entity.dimensions.get("tap.computing") == "runtime", edge

    @pytest.mark.parametrize(
        ("src", "edge", "dst"),
        [
            ("grid", "LOADS_MODULE", "program"),
            ("host", "LOADS_MODULE", "grid"),
            ("package", "LOADS_MODULE", "grid"),
            ("grid", "CONTAINS_MODULE", "package"),
            ("grid", "CONTAINS_MODULE", "library"),
            ("host", "CONTAINS_MODULE", "grid"),
            ("program", "CONTAINS_MODULE", "grid"),
            ("package", "IMPORTS_MODULE", "grid"),
            ("grid", "IMPORTS_MODULE", "package"),
            ("program", "IMPORTS_MODULE", "grid"),
            ("grid", "IMPORTS_MODULE", "program"),
        ],
    )
    def test_the_wrong_way_round_or_wrong_type_is_refused(self, src, edge, dst):
        n = self._nodes()
        with pytest.raises(InvalidEdgeError):
            create_edge(n[src].entity, n[dst].entity, f"{edge}__computing_core")

    def test_plain_identity_and_one_property(self):
        """req-computing-core-module-edges-2 and -5."""
        manifest = tomllib.loads((PLUGIN / "tap-plugin.toml").read_text())
        for slug in EDGE_SLUGS:
            definition = _definition(slug)
            assert definition["slug"] == f"{slug}__computing_core"
            assert manifest["edges"][definition["slug"]] == f"edges/{slug}.edge.json"
            assert definition["identity"] == {"discriminators": []}, slug
            assert definition["default_dimensions"] == {"tap.computing": "runtime"}, slug
            assert definition["description"], slug
            if slug != "IMPORTS_MODULE":
                assert "property_schema" not in definition, slug
        schema = _definition("IMPORTS_MODULE")["property_schema"]
        assert set(schema["properties"]) == {"import_count"}
        assert schema["additionalProperties"] is False
        assert schema["properties"]["import_count"]["description"]

    def test_import_count_is_positive(self):
        """req-computing-core-module-edges-3."""
        n = self._nodes()
        edge = create_edge(n["web"].entity, n["grid"].entity, "IMPORTS_MODULE__computing_core", {"import_count": 3})
        assert edge.properties["import_count"] == 3
        for bad in (0, -1, 1.5, "2", None):
            with pytest.raises(Exception, match=r"(?i)import_count|valid"):
                create_edge(n["gryphon"].entity, n["grid"].entity, "IMPORTS_MODULE__computing_core", {"import_count": bad})
        with pytest.raises(Exception, match=r"(?i)additional|valid"):
            create_edge(n["gryphon"].entity, n["grid"].entity, "IMPORTS_MODULE__computing_core", {"lines": 1})

    def test_only_containment_contains(self):
        """req-computing-core-module-edges-4: retiring a program or an importer leaves the modules."""
        containment = get_model_class(TYPE).CONTAINMENT_EDGES
        assert containment == ("CONTAINS_MODULE__computing_core",)
        for name, model in {
            m: get_model_class(f"computing_core__{m}") for m in ("program", "package", "library", "host")
        }.items():
            assert not {f"{s}__computing_core" for s in ("LOADS_MODULE", "IMPORTS_MODULE")} & set(
                getattr(model, "CONTAINMENT_EDGES", ())
            ), name
        n = self._nodes()
        create_edge(n["program"].entity, n["grid"].entity, "LOADS_MODULE__computing_core")
        create_edge(n["web"].entity, n["grid"].entity, "IMPORTS_MODULE__computing_core", {"import_count": 1})
        assert delete_node(n["program"].entity_id, cascade="contained").success
        assert delete_node(n["web"].entity_id, cascade="contained").success
        n["grid"].entity.refresh_from_db()
        assert n["grid"].entity.deleted_at is None

    def test_retiring_a_parent_retires_its_submodules(self):
        n = self._nodes()
        create_edge(n["grid"].entity, n["gryphon"].entity, "CONTAINS_MODULE__computing_core")
        assert delete_node(n["grid"].entity_id, cascade="contained").success
        n["gryphon"].entity.refresh_from_db()
        assert n["gryphon"].entity.deleted_at is not None
