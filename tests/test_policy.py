"""Automated tests for access control and the SFTP jail."""

import json
import sys
from pathlib import Path

import pytest

# Make server/ importable regardless of where pytest is invoked from.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "server"))

from policy import PolicyEngine  # noqa: E402
from server import safe_join  # noqa: E402


@pytest.fixture
def policy(tmp_path):
    """Set up a few users, roles, and paths with their own audit log."""
    data = tmp_path / "data"
    data.mkdir()
    (data / "user_roles.json").write_text(
        json.dumps({"alice": ["analyst", "admin"], "bob": ["analyst"]}), encoding="utf-8"
    )
    (data / "role_perms.csv").write_text(
        "role,resource,read,write,mkdir,list,stat\n"
        "analyst,/projects,read,write,,list,stat\n"
        "analyst,/public,read,write,,list,stat\n"
        "admin,/admin,,,mkdir,,\n",
        encoding="utf-8",
    )
    (data / "mac_labels.json").write_text(
        json.dumps({
            "users": {"alice": "confidential", "bob": "internal"},
            "paths": {
                "/": "internal",
                "/public": "public",
                "/projects/private": "confidential",
                "/projects/owner.txt": "confidential",
            },
        }),
        encoding="utf-8",
    )
    (data / "dac_owners.csv").write_text(
        "path,owner,group,mode,group_members\n"
        "/,alice,staff,rwxrwxrwx,alice\n"
        "/projects/owner.txt,alice,staff,rw-r-----,alice\n"
        "/no-execute,alice,staff,rwxrwxr--,alice\n",
        encoding="utf-8",
    )
    return PolicyEngine(data, tmp_path / "audit.jsonl")


def test_dac_owner_can_read_and_write(policy):
    """The owner can read and write their own file."""
    path = "/projects/owner.txt"
    assert policy.authorize("alice", "read", path)[0] is True
    assert policy.authorize("alice", "write", path)[0] is True


def test_dac_other_cannot_write(policy):
    """A non-owner without the write bit is denied."""
    allowed, reason = policy.authorize("bob", "write", "/projects/owner.txt")
    assert allowed is False
    assert reason.startswith("DAC deny:")
    assert "other lacking 'w'" in reason


def test_dac_directory_execute_bit(policy):
    """Listing and stat both require the directory execute bit."""
    for op in ("list", "stat"):
        assert policy.authorize("bob", op, "/projects")[0] is True
        allowed, reason = policy.authorize("bob", op, "/no-execute")
        assert allowed is False
        assert reason.startswith("DAC deny:")
        assert "other lacking 'x'" in reason


def test_mac_internal_user_cannot_read_up(policy):
    """An internal user can read public and internal files, but not confidential ones."""
    path = "/projects/private/note.txt"
    assert policy.check_dac("bob", "read", path)[0] is True

    allowed, reason = policy.authorize("bob", "read", path)
    assert allowed is False
    assert reason.startswith("MAC deny:")
    assert "Denied read up" in reason

    assert policy.authorize("bob", "read", "/public/note.txt")[0] is True
    assert policy.authorize("bob", "read", "/projects/note.txt")[0] is True


def test_mac_confidential_user_cannot_write_down(policy):
    """DAC allows writing here, but MAC stops a confidential user writing to public."""
    path = "/public/note.txt"
    assert policy.check_dac("alice", "write", path)[0] is True

    allowed, reason = policy.authorize("alice", "write", path)
    assert allowed is False
    assert reason.startswith("MAC deny:")
    assert "Denied write down" in reason


def test_rbac_adding_admin_role_allows_mkdir(policy):
    """An analyst can read and write in projects and needs admin to mkdir in admin."""
    path = "/admin/demo"
    assert policy.authorize("bob", "read", "/projects/note.txt")[0] is True
    assert policy.authorize("bob", "write", "/projects/note.txt")[0] is True

    allowed, reason = policy.authorize("bob", "mkdir", path)
    assert allowed is False
    assert reason.startswith("RBAC deny:")

    roles_file = policy.data_dir / "user_roles.json"
    roles = json.loads(roles_file.read_text(encoding="utf-8"))
    roles["bob"].append("admin")
    roles_file.write_text(json.dumps(roles), encoding="utf-8")

    restarted_policy = PolicyEngine(policy.data_dir, policy.audit_path)
    assert restarted_policy.authorize("bob", "mkdir", path)[0] is True


def test_jail_rejects_path_outside_root(tmp_path):
    """A path pointing at a file outside the temporary jail is rejected."""
    jail = tmp_path / "jail"
    jail.mkdir()
    (tmp_path / "outside.txt").write_text("outside the jail", encoding="utf-8")

    with pytest.raises(PermissionError, match="path escape"):
        safe_join(str(jail), b"../outside.txt")
