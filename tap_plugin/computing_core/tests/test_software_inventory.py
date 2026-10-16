"""Tests for the software-inventory vocabulary: `package`, `library`, `operating_system`,
`crypto_provider` and the five edges between them and `host` / `program`.

req-computing-core-package, -library, -operating-system, -crypto-provider and
-inventory-edges. Creation through the service layer, required fields, the declared natural
keys (found again by the generated search), closed vocabularies, the edges' endpoint rules,
and that none of the edges is containment. No collector exists for these types yet; the
payloads below are the shapes tap's SBOM and crypto-BOM produce for the Wolfi-based tap-web image.
"""

import json
from pathlib import Path

import pytest
import tap_plugin.computing_core.models as computing  # noqa: F401 — trigger model registration

from tap_grid.constraints import InvalidEdgeError
from tap_grid.models import Edge, Entity
from tap_grid.registry import get_model_class
from tap_grid.services import create_edge, create_node, delete_node

EDGES = Path(__file__).resolve().parents[1] / "edges"

PACKAGE = {"ecosystem": "apk", "name": "glibc", "version": "2.44-r6", "architecture": "x86_64"}
LIBRARY = {
    "ecosystem": "generic",
    "name": "openssl-fips-provider",
    "version": "3.5.8",
    "language": "c",
    "source_kind": "self-built",
    "path": "/usr/lib/ossl-modules/fips.so",
}
SOURCE_PACKAGE = {"ecosystem": "apk", "name": "glibc", "version": "2.44-r6"}
SBOM_DOCUMENT = {"content_digest": "ab" * 32}
WOLFI = {"os_id": "wolfi", "version_id": "20230201", "build_id": "sha256:" + "a" * 64, "rolling": True}
PROVIDER = {
    "scope": "tap-web",
    "artifact": "/usr/bin/uv",
    "provider": "rust-aws-lc-rs",
    "provider_kind": "non-openssl",
    "boundary": "out-of-boundary",
}
HOST = {"realm": "assert", "stable_id": "tap-web-image", "kind": "container"}


def _create(type_slug: str, payload: dict):
    """Create a node via the service layer and return the typed domain object."""
    result = create_node(type_slug, payload)
    assert result.success, f"create_node failed: {result.errors}"
    return get_model_class(type_slug).objects.get(entity=Entity.objects.get(pk=result.entity_id))


@pytest.mark.django_db
class TestPackage:
    def test_create_and_display(self):
        node = _create("computing_core__package", {**PACKAGE, "purl": "pkg:apk/wolfi/glibc@2.44-r6?arch=x86_64"})
        node.entity.refresh_from_db()
        assert node.entity.name == "glibc 2.44-r6"
        assert node.entity.dimensions.get("tap.computing") == "runtime"
        assert node.source_document == ""

    @pytest.mark.parametrize("missing", ["ecosystem", "name", "version"])
    def test_key_fields_required(self, missing):
        payload = {k: v for k, v in PACKAGE.items() if k != missing}
        assert not create_node("computing_core__package", payload).success

    def test_found_again_by_ecosystem_name_and_version(self):
        node = _create("computing_core__package", PACKAGE)
        model = get_model_class("computing_core__package")
        assert model.find_existing(ecosystem="apk", name="glibc", version="2.44-r6").pk == node.pk
        assert model.find_existing(ecosystem="apk", name="glibc", version="2.44-r7") is None
        assert model.find_existing(ecosystem="pypi", name="glibc", version="2.44-r6") is None

    def test_architecture_and_source_document_are_not_identity(self):
        node = _create("computing_core__package", {**PACKAGE, "source_document": "sbom"})
        node.architecture = "aarch64"
        node.source_document = "uv.lock"
        node.save()
        found = get_model_class("computing_core__package").find_existing(
            ecosystem="apk", name="glibc", version="2.44-r6"
        )
        assert found.pk == node.pk
        assert (found.architecture, found.source_document) == ("aarch64", "uv.lock")

    def test_ecosystem_is_a_purl_type(self):
        assert create_node("computing_core__package", {**PACKAGE, "ecosystem": "pypi"}).success
        assert not create_node("computing_core__package", {**PACKAGE, "ecosystem": "APK"}).success
        assert not create_node("computing_core__package", {**PACKAGE, "ecosystem": ""}).success

    def test_whole_purl_is_stored_as_given(self):
        """req-computing-core-package-6: arch, distro and upstream survive a write and a read."""
        purl = "pkg:apk/wolfi/libssl3@3.6.4-r8?arch=aarch64&distro=wolfi-20230201&upstream=openssl"
        node = _create("computing_core__package", {**PACKAGE, "name": "libssl3", "purl": purl})
        node.refresh_from_db()
        assert node.purl == purl

    def test_cpe_candidates_default_to_the_empty_list(self):
        """req-computing-core-package-7."""
        node = _create("computing_core__package", PACKAGE)
        node.refresh_from_db()
        assert node.cpe_candidates == []

    def test_cpe_candidates_hold_a_list_of_cpe23_names(self):
        candidates = [
            "cpe:2.3:a:libssl3:libssl:3.6.4-r8:*:*:*:*:*:*:*",
            "cpe:2.3:a:libssl:libssl:3.6.4-r8:*:*:*:*:*:*:*",
        ]
        node = _create(
            "computing_core__package",
            {**PACKAGE, "cpe": "cpe:2.3:a:libssl3:libssl3:3.6.4-r8:*:*:*:*:*:*:*", "cpe_candidates": candidates},
        )
        node.refresh_from_db()
        assert node.cpe_candidates == candidates

    @pytest.mark.parametrize(
        "bad",
        [
            "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*",  # a bare string, not a list
            ["cpe:/a:x:y:1"],  # CPE 2.2, not 2.3
            ["not a cpe"],
            [None],
            [5],
            ["cpe:2.3:a:x:y:1:*:*:*:*:*:*:*", "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"],  # repeated entry
        ],
    )
    def test_cpe_candidates_refuse_anything_else(self, bad):
        assert not create_node("computing_core__package", {**PACKAGE, "cpe_candidates": bad}).success

    def test_cpe_candidates_never_repeat_cpe(self):
        cpe = "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"
        assert not create_node("computing_core__package", {**PACKAGE, "cpe": cpe, "cpe_candidates": [cpe]}).success

    def test_cpe_candidates_are_declared_in_both_schemas(self):
        """A JSON column with no schema is `{type: object}` and blocks strict validation."""
        model = get_model_class("computing_core__package")
        assert model.FIELD_CRUD_SCHEMA["cpe_candidates"]["type"] == "array"
        assert model.FIELD_VALIDATION_SCHEMA["cpe_candidates"]["schema"]["type"] == "array"

    def test_candidates_are_not_identity(self):
        node = _create("computing_core__package", PACKAGE)
        node.cpe_candidates = ["cpe:2.3:a:glibc:glibc:2.44:*:*:*:*:*:*:*"]
        node.save()
        found = get_model_class("computing_core__package").find_existing(
            ecosystem="apk", name="glibc", version="2.44-r6"
        )
        assert found.pk == node.pk

    def test_architecture_is_one_value_never_a_join(self):
        """req-computing-core-package-8: `aarch64, x86_64` in one column is refused."""
        for one in ("x86_64", "aarch64", "noarch", ""):
            assert create_node("computing_core__package", {**PACKAGE, "name": f"ok-{one}", "architecture": one}).success
        for joined in ("aarch64, x86_64", "aarch64,x86_64", "x86_64 aarch64"):
            assert not create_node("computing_core__package", {**PACKAGE, "architecture": joined}).success


@pytest.mark.django_db
class TestSourcePackage:
    def test_create_and_display(self):
        node = _create("computing_core__source_package", SOURCE_PACKAGE)
        node.entity.refresh_from_db()
        assert node.entity.name == "glibc 2.44-r6"
        assert node.entity.dimensions.get("tap.computing") == "runtime"

    @pytest.mark.parametrize("missing", ["ecosystem", "name", "version"])
    def test_key_fields_required(self, missing):
        payload = {k: v for k, v in SOURCE_PACKAGE.items() if k != missing}
        assert not create_node("computing_core__source_package", payload).success

    def test_found_again_by_ecosystem_name_and_version(self):
        node = _create("computing_core__source_package", SOURCE_PACKAGE)
        model = get_model_class("computing_core__source_package")
        assert model.find_existing(ecosystem="apk", name="glibc", version="2.44-r6").pk == node.pk
        assert model.find_existing(ecosystem="apk", name="glibc", version="2.44-r7") is None
        assert model.find_existing(ecosystem="deb", name="glibc", version="2.44-r6") is None

    def test_ecosystem_is_a_purl_type(self):
        assert create_node("computing_core__source_package", {**SOURCE_PACKAGE, "ecosystem": "deb"}).success
        assert not create_node("computing_core__source_package", {**SOURCE_PACKAGE, "ecosystem": "APK"}).success
        assert not create_node("computing_core__source_package", {**SOURCE_PACKAGE, "ecosystem": ""}).success

    def test_it_holds_the_key_and_nothing_else(self):
        """purl, cpe, license and architecture are facts about an installed binary; they stay on `package`."""
        own = {f.name for f in get_model_class("computing_core__source_package")._meta.concrete_fields}
        assert {"ecosystem", "name", "version"} <= own
        assert not own & {"purl", "cpe", "license", "architecture", "source_document"}

    def test_a_package_and_its_source_package_are_two_nodes(self):
        """An origin that is the package itself (47 of 101 in the tap-web image) is still two nodes."""
        pkg = _create("computing_core__package", {"ecosystem": "apk", "name": "zlib", "version": "1.3.1-r5"})
        src = _create("computing_core__source_package", {"ecosystem": "apk", "name": "zlib", "version": "1.3.1-r5"})
        assert pkg.entity.entity_type != src.entity.entity_type
        assert pkg.entity_id != src.entity_id


@pytest.mark.django_db
class TestLibrary:
    def test_create_and_display(self):
        node = _create("computing_core__library", LIBRARY)
        node.entity.refresh_from_db()
        assert node.entity.name == "openssl-fips-provider 3.5.8"
        assert node.entity.dimensions.get("tap.computing") == "runtime"

    @pytest.mark.parametrize("missing", ["ecosystem", "name", "version"])
    def test_key_fields_required(self, missing):
        payload = {k: v for k, v in LIBRARY.items() if k != missing}
        assert not create_node("computing_core__library", payload).success

    def test_source_kind_is_a_closed_vocabulary_and_null_is_unobserved(self):
        base = {"ecosystem": "pypi", "name": "cryptography", "version": "46.0.0"}
        assert _create("computing_core__library", base).source_kind is None
        assert create_node(
            "computing_core__library", {**base, "version": "46.0.1", "source_kind": "source-built"}
        ).success
        assert not create_node(
            "computing_core__library", {**base, "version": "46.0.2", "source_kind": "downloaded"}
        ).success

    def test_a_package_and_a_library_of_one_name_are_two_nodes(self):
        pkg = _create("computing_core__package", {"ecosystem": "pypi", "name": "cryptography", "version": "46.0.0"})
        lib = _create("computing_core__library", {"ecosystem": "pypi", "name": "cryptography", "version": "46.0.0"})
        assert pkg.entity.entity_type != lib.entity.entity_type

    def test_cryptography_is_an_edge_not_a_column(self):
        fields = {f.name for f in get_model_class("computing_core__library")._meta.get_fields()}
        assert not {f for f in fields if "crypto" in f}


@pytest.mark.django_db
class TestOperatingSystem:
    def test_create_and_display(self):
        node = _create(
            "computing_core__operating_system",
            {**WOLFI, "name": "Wolfi", "vendor": "Chainguard", "end_of_life": "2030-01-31"},
        )
        node.entity.refresh_from_db()
        assert node.entity.name == "Wolfi"
        assert node.version_id == "20230201"
        assert node.rolling is True
        assert str(node.end_of_life) == "2030-01-31"
        assert node.entity.dimensions.get("tap.computing") == "runtime"

    def test_name_falls_back_to_os_id(self):
        node = _create("computing_core__operating_system", {"os_id": "debian", "version_id": "13", "build_id": ""})
        node.entity.refresh_from_db()
        assert node.entity.name == "debian"

    def test_a_placeholder_version_id_does_not_merge_two_builds(self):
        a = _create("computing_core__operating_system", WOLFI)
        b = _create("computing_core__operating_system", {**WOLFI, "build_id": "sha256:" + "b" * 64})
        assert a.pk != b.pk
        model = get_model_class("computing_core__operating_system")
        assert model.find_existing(os_id="wolfi", version_id="20230201", build_id=WOLFI["build_id"]).pk == a.pk

    def test_found_again_across_a_rename_of_the_display_name(self):
        node = _create("computing_core__operating_system", {**WOLFI, "name": "Wolfi"})
        node.name = "Wolfi OS"
        node.save()
        model = get_model_class("computing_core__operating_system")
        assert model.find_existing(**{k: WOLFI[k] for k in ("os_id", "version_id", "build_id")}).pk == node.pk

    @pytest.mark.parametrize("missing", ["os_id", "version_id", "build_id"])
    def test_every_key_part_must_be_present(self, missing):
        payload = {k: v for k, v in WOLFI.items() if k != missing}
        assert not create_node("computing_core__operating_system", payload).success

    def test_os_id_must_not_be_empty_but_the_others_may_be(self):
        assert not create_node("computing_core__operating_system", {**WOLFI, "os_id": ""}).success
        assert create_node(
            "computing_core__operating_system", {"os_id": "arch", "version_id": "", "build_id": ""}
        ).success

    def test_rolling_and_end_of_life_default_to_unobserved(self):
        node = _create("computing_core__operating_system", {"os_id": "ubuntu", "version_id": "24.04", "build_id": ""})
        assert node.rolling is None
        assert node.end_of_life is None

    @pytest.mark.parametrize("bad", ["2030", "31-01-2030", "soon"])
    def test_end_of_life_is_an_iso_date(self, bad):
        assert not create_node("computing_core__operating_system", {**WOLFI, "end_of_life": bad}).success

    def test_host_os_stays_the_free_text_report(self):
        node = _create("computing_core__host", {**HOST, "os": "wolfi"})
        assert node.os == "wolfi"


@pytest.mark.django_db
class TestCryptoProvider:
    def test_create_and_display(self):
        node = _create("computing_core__crypto_provider", {**PROVIDER, "rationale": "provisioning-time only"})
        node.entity.refresh_from_db()
        assert node.entity.name == "rust-aws-lc-rs (/usr/bin/uv)"
        assert node.boundary == "out-of-boundary"
        assert node.entity.dimensions.get("tap.computing") == "runtime"

    @pytest.mark.parametrize("missing", ["scope", "artifact", "provider", "provider_kind"])
    def test_required_fields(self, missing):
        payload = {k: v for k, v in PROVIDER.items() if k != missing}
        assert not create_node("computing_core__crypto_provider", payload).success

    def test_found_again_by_scope_artifact_and_provider(self):
        node = _create("computing_core__crypto_provider", PROVIDER)
        node.boundary = "must-fix"
        node.save()
        model = get_model_class("computing_core__crypto_provider")
        key = {"scope": "tap-web", "artifact": "/usr/bin/uv", "provider": "rust-aws-lc-rs"}
        assert model.find_existing(**key).pk == node.pk
        assert model.find_existing(**{**key, "scope": "tap-db"}) is None

    @pytest.mark.parametrize(
        "boundary", ["validated", "fips-mode-unvalidated-build", "out-of-boundary", "unreached", "must-fix"]
    )
    def test_every_registry_boundary_is_accepted(self, boundary):
        assert create_node("computing_core__crypto_provider", {**PROVIDER, "boundary": boundary}).success

    def test_boundary_is_closed_and_null_is_unclassified(self):
        assert not create_node("computing_core__crypto_provider", {**PROVIDER, "boundary": "probably-fine"}).success
        unclassified = {k: v for k, v in PROVIDER.items() if k != "boundary"}
        assert _create("computing_core__crypto_provider", unclassified).boundary is None

    def test_provider_kind_is_closed(self):
        assert not create_node("computing_core__crypto_provider", {**PROVIDER, "provider_kind": "magic"}).success

    def test_it_has_no_field_that_could_hold_key_material(self):
        fields = {f.name for f in get_model_class("computing_core__crypto_provider")._meta.concrete_fields}
        assert fields >= {"scope", "artifact", "provider", "provider_kind", "boundary", "rationale", "fips_validation"}
        assert not {f for f in fields if any(w in f for w in ("key", "fingerprint", "secret", "content", "hash"))}


@pytest.mark.django_db
class TestEdges:
    def _nodes(self):
        return {
            "host": _create("computing_core__host", HOST),
            "package": _create("computing_core__package", PACKAGE),
            "dependency": _create("computing_core__package", {**PACKAGE, "name": "glibc-dev"}),
            "sbom": _create("computing_core__sbom_document", SBOM_DOCUMENT),
            "source_package": _create("computing_core__source_package", SOURCE_PACKAGE),
            "library": _create("computing_core__library", LIBRARY),
            "program": _create("computing_core__program", {"program_name": "python3.14"}),
            "os": _create("computing_core__operating_system", WOLFI),
            "provider": _create("computing_core__crypto_provider", PROVIDER),
        }

    def test_the_sentences_connect(self):
        n = self._nodes()
        for src, edge, dst in [
            ("host", "INSTALLS_PACKAGE", "package"),
            ("package", "SHIPS_LIBRARY", "library"),
            ("package", "DERIVES_FROM_SOURCE_PACKAGE", "source_package"),
            ("package", "REQUIRES_PACKAGE", "dependency"),
            ("sbom", "DESCRIBES_HOST", "host"),
            ("program", "LOADS_LIBRARY", "library"),
            ("host", "RUNS_OPERATING_SYSTEM", "os"),
            ("library", "CARRIES_CRYPTO_PROVIDER", "provider"),
            ("package", "CARRIES_CRYPTO_PROVIDER", "provider"),
            ("program", "CARRIES_CRYPTO_PROVIDER", "provider"),
        ]:
            created = create_edge(n[src].entity, n[dst].entity, f"{edge}__computing_core")
            assert created.entity.dimensions.get("tap.computing") == "runtime", edge

    @pytest.mark.parametrize(
        ("src", "edge", "dst"),
        [
            ("package", "INSTALLS_PACKAGE", "host"),
            ("library", "INSTALLS_PACKAGE", "package"),
            ("host", "SHIPS_LIBRARY", "library"),
            ("library", "LOADS_LIBRARY", "program"),
            ("host", "LOADS_LIBRARY", "library"),
            ("package", "RUNS_OPERATING_SYSTEM", "os"),
            ("provider", "CARRIES_CRYPTO_PROVIDER", "library"),
            ("host", "CARRIES_CRYPTO_PROVIDER", "provider"),
            ("source_package", "DERIVES_FROM_SOURCE_PACKAGE", "package"),
            ("host", "DERIVES_FROM_SOURCE_PACKAGE", "source_package"),
            ("package", "DERIVES_FROM_SOURCE_PACKAGE", "library"),
            ("library", "DERIVES_FROM_SOURCE_PACKAGE", "source_package"),
            ("package", "REQUIRES_PACKAGE", "library"),
            ("library", "REQUIRES_PACKAGE", "package"),
            ("host", "REQUIRES_PACKAGE", "package"),
            ("package", "REQUIRES_PACKAGE", "source_package"),
            ("host", "DESCRIBES_HOST", "sbom"),
            ("sbom", "DESCRIBES_HOST", "package"),
            ("package", "DESCRIBES_HOST", "host"),
            ("sbom", "INSTALLS_PACKAGE", "package"),
        ],
    )
    def test_the_wrong_way_round_or_wrong_type_is_refused(self, src, edge, dst):
        # Refused wherever an endpoint type declares its edges. The grid permits an edge when the
        # source's OUTBOUND_EDGES or the edge definition's `sources` allows it, and again for the
        # target, so a side whose type declares nothing (`program`) is open: the pairs below are
        # the ones the declarations on package, library, host and the new types close.
        n = self._nodes()
        with pytest.raises(InvalidEdgeError):
            create_edge(n[src].entity, n[dst].entity, f"{edge}__computing_core")

    def test_every_edge_declares_the_plain_identity_and_no_properties(self):
        for slug in (
            "INSTALLS_PACKAGE",
            "SHIPS_LIBRARY",
            "DERIVES_FROM_SOURCE_PACKAGE",
            "REQUIRES_PACKAGE",
            "DESCRIBES_HOST",
            "LOADS_LIBRARY",
            "RUNS_OPERATING_SYSTEM",
            "CARRIES_CRYPTO_PROVIDER",
        ):
            definition = json.loads((EDGES / f"{slug}.edge.json").read_text())
            assert definition["slug"] == f"{slug}__computing_core"
            assert definition["identity"] == {"discriminators": []}, slug
            assert "property_schema" not in definition, slug
            assert definition["default_dimensions"] == {"tap.computing": "runtime"}, slug

    def test_none_of_them_is_containment(self):
        """Retiring a host leaves the shared package, library, OS and provider it pointed at."""
        n = self._nodes()
        create_edge(n["host"].entity, n["package"].entity, "INSTALLS_PACKAGE__computing_core")
        create_edge(n["host"].entity, n["os"].entity, "RUNS_OPERATING_SYSTEM__computing_core")
        create_edge(n["package"].entity, n["library"].entity, "SHIPS_LIBRARY__computing_core")
        create_edge(n["package"].entity, n["source_package"].entity, "DERIVES_FROM_SOURCE_PACKAGE__computing_core")
        create_edge(n["library"].entity, n["provider"].entity, "CARRIES_CRYPTO_PROVIDER__computing_core")
        create_edge(n["package"].entity, n["dependency"].entity, "REQUIRES_PACKAGE__computing_core")
        create_edge(n["sbom"].entity, n["host"].entity, "DESCRIBES_HOST__computing_core")

        assert delete_node(n["host"].entity_id, cascade="contained").success

        n["host"].entity.refresh_from_db()
        assert n["host"].entity.deleted_at is not None
        for name in ("package", "dependency", "sbom", "source_package", "library", "os", "provider"):
            n[name].entity.refresh_from_db()
            assert n[name].entity.deleted_at is None, name

    def test_retiring_a_package_leaves_the_packages_it_required(self):
        """req-computing-core-package-dependency-2: a dependency outlives the package that named it."""
        n = self._nodes()
        create_edge(n["package"].entity, n["dependency"].entity, "REQUIRES_PACKAGE__computing_core")
        assert delete_node(n["package"].entity_id, cascade="contained").success
        n["dependency"].entity.refresh_from_db()
        assert n["dependency"].entity.deleted_at is None

    def test_one_source_package_has_many_packages_and_a_self_origin_still_gets_the_edge(self):
        """req-computing-core-source-package-4: the glibc case from the issue, plus a package that is its own source."""
        source = _create("computing_core__source_package", SOURCE_PACKAGE)
        names = ("glibc", "glibc-dev", "glibc-locale-posix", "ld-linux", "libcrypt1")
        for name in names:  # `glibc` is its own origin; the rest are built from the same source
            package = _create("computing_core__package", {**PACKAGE, "name": name})
            create_edge(package.entity, source.entity, "DERIVES_FROM_SOURCE_PACKAGE__computing_core")
        edges = Edge.objects.filter(edge_type="DERIVES_FROM_SOURCE_PACKAGE__computing_core", to_entity=source.entity)
        assert edges.count() == len(names)

    def test_a_scanner_finding_attaches_to_a_package_or_a_library(self):
        """req-computing-core-package-5: the existing compliance edge, no new finding edge.

        The edge lives in compliance_core, which computing_core does not depend on, so this runs
        only on a grid that has it installed (as `os_user`'s HELD_BY_HUMAN does).
        """
        finding_type = "compliance_core__compliance_finding"
        try:
            get_model_class(finding_type)
        except Exception:  # noqa: BLE001 — any lookup failure means the plugin is not installed
            pytest.skip("compliance_core is not installed in this stack")
        n = self._nodes()
        result = create_node(
            finding_type,
            {"source": "scanner", "source_key": "CVE-2026-0001#glibc", "name": "CVE-2026-0001 in glibc"},
        )
        assert result.success, result.errors
        finding = Entity.objects.get(pk=result.entity_id)
        for target in (n["package"], n["library"]):
            create_edge(target.entity, finding, "CARRIES_COMPLIANCE_FINDING__compliance_core")
