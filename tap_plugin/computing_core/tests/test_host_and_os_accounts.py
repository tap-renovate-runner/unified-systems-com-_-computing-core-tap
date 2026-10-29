"""Tests for `host`, `os_user`, `os_group` and the three edges between them.

req-computing-core-host and req-computing-core-os-accounts: creation through the service layer,
required fields, the declared natural keys (found again by the generated search, and a rename
staying one row), the edges' endpoint and property rules, and the delete tree (a host's local
accounts and groups retire with it; a group's members do not).
"""

import pytest
import tap_plugin.computing_core.models as computing  # noqa: F401 — trigger model registration

from tap_grid.constraints import EdgePropertyValidationError, InvalidEdgeError
from tap_grid.models import Edge, Entity
from tap_grid.registry import get_model_class
from tap_grid.services import create_edge, create_node, delete_node

HOST = {"realm": "machine-id", "stable_id": "4c4c4544-0042-3510-8051-b4c04f4b4e31", "name": "build-01"}
ON_HOST = {"host_realm": HOST["realm"], "host_stable_id": HOST["stable_id"]}


def _create(type_slug: str, payload: dict):
    """Create a node via the service layer and return the typed domain object."""
    result = create_node(type_slug, payload)
    assert result.success, f"create_node failed: {result.errors}"
    return get_model_class(type_slug).objects.get(entity=Entity.objects.get(pk=result.entity_id))


@pytest.mark.django_db
class TestHost:
    def test_create_and_display(self):
        node = _create("computing_core__host", {**HOST, "kind": "server", "os": "linux", "ephemeral": False})
        node.entity.refresh_from_db()
        assert node.entity.name == "build-01"
        assert (node.kind, node.os, node.ephemeral) == ("server", "linux", False)
        assert node.entity.dimensions.get("tap.computing") == "host"

    def test_name_falls_back_to_stable_id(self):
        node = _create("computing_core__host", {"realm": "aws-ec2", "stable_id": "i-0abc"})
        node.entity.refresh_from_db()
        assert node.entity.name == "i-0abc"

    def test_kind_and_ephemeral_default_to_unobserved(self):
        node = _create("computing_core__host", {"realm": "aws-ec2", "stable_id": "i-0abc"})
        assert node.kind is None
        assert node.ephemeral is None

    @pytest.mark.parametrize("missing", ["realm", "stable_id"])
    def test_key_fields_required(self, missing):
        payload = {k: v for k, v in HOST.items() if k != missing}
        assert not create_node("computing_core__host", payload).success

    def test_kind_is_a_closed_vocabulary(self):
        assert create_node("computing_core__host", {**HOST, "kind": "unknown"}).success
        assert not create_node("computing_core__host", {"realm": "r", "stable_id": "s", "kind": "mainframe"}).success

    def test_found_again_by_realm_and_stable_id_across_a_rename(self):
        node = _create("computing_core__host", HOST)
        node.name = "build-01-renamed"
        node.save()
        model = get_model_class("computing_core__host")
        assert model.find_existing(realm=HOST["realm"], stable_id=HOST["stable_id"]).pk == node.pk
        assert model.find_existing(realm="aws-ec2", stable_id=HOST["stable_id"]) is None


DIGEST = "sha256:" + "ab12" * 16


@pytest.mark.django_db
class TestImageHost:
    """req-computing-core-host-4: an ``oci-digest`` host's stable_id is a sha256 digest."""

    def test_a_digest_makes_an_image_host(self):
        node = _create(
            "computing_core__host",
            {"realm": "oci-digest", "stable_id": DIGEST, "name": "ghcr.io/org/app:1.2", "kind": "container"},
        )
        node.entity.refresh_from_db()
        assert (node.realm, node.stable_id, node.kind) == ("oci-digest", DIGEST, "container")
        assert node.entity.name == "ghcr.io/org/app:1.2"

    @pytest.mark.parametrize(
        "bad",
        [
            "ghcr.io/org/app:1.2",  # a tag is not a digest
            "sha256:" + "AB12" * 16,  # upper case
            "sha256:" + "ab12" * 15,  # too short
            "sha256:" + "ab12" * 17,  # too long
            "sha512:" + "ab12" * 16,  # another algorithm
            DIGEST + "\n",  # a trailing newline must not pass
        ],
    )
    def test_anything_but_a_sha256_digest_is_refused(self, bad):
        assert not create_node("computing_core__host", {"realm": "oci-digest", "stable_id": bad}).success

    def test_the_same_digest_is_one_host_and_other_realms_are_unchecked(self):
        node = _create("computing_core__host", {"realm": "oci-digest", "stable_id": DIGEST})
        model = get_model_class("computing_core__host")
        assert model.find_existing(realm="oci-digest", stable_id=DIGEST).pk == node.pk
        # another authority may use any shape; the pattern is the oci-digest realm's alone
        assert create_node("computing_core__host", {"realm": "assert", "stable_id": "not-a-digest"}).success


@pytest.mark.django_db
class TestOsUser:
    def test_windows_account_keeps_its_sid_across_a_rename(self):
        sid = "S-1-5-21-3623811015-3361044348-30300820-500"
        node = _create("computing_core__os_user", {**ON_HOST, "local_id": sid, "name": "Administrator"})
        node.name = "ops-admin"
        node.save()
        node.entity.refresh_from_db()
        assert node.entity.name == "ops-admin"
        found = get_model_class("computing_core__os_user").find_existing(**ON_HOST, local_id=sid)
        assert found.pk == node.pk
        assert node.uid is None

    def test_posix_account(self):
        node = _create("computing_core__os_user", {**ON_HOST, "local_id": "deploy", "name": "deploy", "uid": 1001})
        assert node.uid == 1001
        assert node.entity.dimensions.get("tap.computing") == "identity"

    def test_two_posix_names_sharing_one_uid_are_two_accounts(self):
        _create("computing_core__os_user", {**ON_HOST, "local_id": "root", "uid": 0})
        _create("computing_core__os_user", {**ON_HOST, "local_id": "toor", "uid": 0})
        model = get_model_class("computing_core__os_user")
        assert model.find_existing(**ON_HOST, local_id="root") != model.find_existing(**ON_HOST, local_id="toor")

    def test_same_name_on_two_hosts_is_two_accounts(self):
        a = _create("computing_core__os_user", {**ON_HOST, "local_id": "root"})
        b = _create(
            "computing_core__os_user", {"host_realm": "aws-ec2", "host_stable_id": "i-0abc", "local_id": "root"}
        )
        assert a.pk != b.pk

    @pytest.mark.parametrize("missing", ["host_realm", "host_stable_id", "local_id"])
    def test_key_fields_required(self, missing):
        payload = {**ON_HOST, "local_id": "deploy"}
        del payload[missing]
        assert not create_node("computing_core__os_user", payload).success

    def test_uid_is_not_negative(self):
        assert not create_node("computing_core__os_user", {**ON_HOST, "local_id": "x", "uid": -1}).success


@pytest.mark.django_db
class TestOsGroup:
    def test_create_and_key(self):
        node = _create("computing_core__os_group", {**ON_HOST, "local_id": "wheel", "name": "wheel", "gid": 10})
        node.entity.refresh_from_db()
        assert node.entity.name == "wheel"
        assert node.entity.dimensions.get("tap.computing") == "identity"
        assert get_model_class("computing_core__os_group").find_existing(**ON_HOST, local_id="wheel").pk == node.pk

    @pytest.mark.parametrize("missing", ["host_realm", "host_stable_id", "local_id"])
    def test_key_fields_required(self, missing):
        payload = {**ON_HOST, "local_id": "wheel"}
        del payload[missing]
        assert not create_node("computing_core__os_group", payload).success


@pytest.mark.django_db
class TestEdges:
    def _host_user_group(self):
        host = _create("computing_core__host", HOST)
        user = _create("computing_core__os_user", {**ON_HOST, "local_id": "deploy"})
        group = _create("computing_core__os_group", {**ON_HOST, "local_id": "docker"})
        return host, user, group

    def test_the_sentences_connect(self):
        host, user, group = self._host_user_group()
        defines_user = create_edge(host.entity, user.entity, "DEFINES_OS_USER__computing_core")
        create_edge(host.entity, group.entity, "DEFINES_OS_GROUP__computing_core")
        member = create_edge(user.entity, group.entity, "MEMBER_OF_GROUP__computing_core", {"primary": False})
        assert member.properties == {"primary": False}
        assert defines_user.entity.dimensions.get("tap.computing") == "identity"

    def test_member_of_group_refuses_unknown_properties(self):
        host, user, group = self._host_user_group()
        with pytest.raises(EdgePropertyValidationError):
            create_edge(user.entity, group.entity, "MEMBER_OF_GROUP__computing_core", {"via": "nested"})

    def test_a_host_defines_nothing_else(self):
        host, user, group = self._host_user_group()
        with pytest.raises(InvalidEdgeError):
            create_edge(host.entity, group.entity, "DEFINES_OS_USER__computing_core")

    def test_a_group_is_not_a_member_of_a_user(self):
        host, user, group = self._host_user_group()
        with pytest.raises(InvalidEdgeError):
            create_edge(group.entity, user.entity, "MEMBER_OF_GROUP__computing_core")

    def test_a_host_retires_its_accounts_and_groups(self):
        host, user, group = self._host_user_group()
        create_edge(host.entity, user.entity, "DEFINES_OS_USER__computing_core")
        create_edge(host.entity, group.entity, "DEFINES_OS_GROUP__computing_core")
        create_edge(user.entity, group.entity, "MEMBER_OF_GROUP__computing_core")

        assert delete_node(host.entity_id, cascade="contained").success

        for node in (host, user, group):
            node.entity.refresh_from_db()
            assert node.entity.deleted_at is not None, node.entity.entity_type

    def test_retiring_a_group_leaves_its_members(self):
        host, user, group = self._host_user_group()
        member = create_edge(user.entity, group.entity, "MEMBER_OF_GROUP__computing_core")

        assert delete_node(group.entity_id, cascade="contained").success

        user.entity.refresh_from_db()
        assert user.entity.deleted_at is None
        assert Edge.objects.filter(pk=member.pk, entity__deleted_at__isnull=True).count() == 0
