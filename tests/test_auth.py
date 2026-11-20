"""
Automated tests for the authentication subsystem (server/auth.py).

Covers (project part: AuthN / login & user setup):
  * valid passwords verify and authenticate;
  * invalid passwords are rejected;
  * malformed / missing user datasets fail cleanly with a readable error;
  * login throttling locks an account after repeated failures;
  * unknown usernames are rejected without leaking existence.

Run with:  python3 -m pytest tests/test_auth.py -v
"""

import base64
import json
import os
import sys
from pathlib import Path

import pytest

# Make server/ importable regardless of where pytest is invoked from.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "server"))

import auth  # noqa: E402


# Fixtures
@pytest.fixture
def users_file(tmp_path):
    """A small, self-contained users.json with known plaintext passwords."""
    passwords = {"carol": "Carol-pw-1!", "dave": "Dave-pw-2!"}
    records = []
    for name, pw in passwords.items():
        rec = auth.hash_password(pw)
        records.append({"username": name, **rec})
    path = tmp_path / "users.json"
    path.write_text(json.dumps(records), encoding="utf-8")
    return path, passwords


# Hash / verify primitives
def test_hash_password_record_shape():
    """hash_password returns base64 salt/hash plus scrypt parameters."""
    rec = auth.hash_password("hunter2")
    for key in ("salt", "password_hash", "n", "r", "p", "dklen"):
        assert key in rec
    # salt and hash are valid base64
    base64.b64decode(rec["salt"])
    base64.b64decode(rec["password_hash"])


def test_hash_password_salt_is_random():
    """Two hashes of the same password use different salts and differ."""
    a = auth.hash_password("same-password")
    b = auth.hash_password("same-password")
    assert a["salt"] != b["salt"]
    assert a["password_hash"] != b["password_hash"]


def test_verify_valid_password():
    """A correct password verifies against its own record."""
    rec = auth.hash_password("correct horse battery staple")
    assert auth.verify_password("correct horse battery staple", rec) is True


def test_verify_invalid_password():
    """An incorrect password is rejected."""
    rec = auth.hash_password("correct horse battery staple")
    assert auth.verify_password("Tr0ub4dor&3", rec) is False


def test_verify_malformed_record_returns_false():
    """A corrupt record is rejected rather than raising."""
    rec = auth.hash_password("pw")
    rec["salt"] = "!!!not base64!!!"
    assert auth.verify_password("pw", rec) is False


# Dataset loading
def test_load_users_ok(users_file):
    """A well-formed users file loads into a username -> record mapping."""
    path, passwords = users_file
    users = auth.load_users(path)
    assert set(users) == set(passwords)


def test_load_users_missing_file(tmp_path):
    """A missing users file raises a readable AuthError."""
    with pytest.raises(auth.AuthError):
        auth.load_users(tmp_path / "does_not_exist.json")


def test_load_users_invalid_json(tmp_path):
    """Invalid JSON is reported as a fatal AuthError."""
    bad = tmp_path / "users.json"
    bad.write_text("{ this is not json", encoding="utf-8")
    with pytest.raises(auth.AuthError):
        auth.load_users(bad)


def test_load_users_missing_field(tmp_path):
    """A user object missing required fields fails cleanly."""
    bad = tmp_path / "users.json"
    bad.write_text(json.dumps([{"username": "x", "salt": "AA=="}]), encoding="utf-8")
    with pytest.raises(auth.AuthError):
        auth.load_users(bad)


def test_load_users_duplicate_username(tmp_path):
    """Duplicate usernames are rejected."""
    rec = auth.hash_password("pw")
    dup = [{"username": "x", **rec}, {"username": "x", **rec}]
    bad = tmp_path / "users.json"
    bad.write_text(json.dumps(dup), encoding="utf-8")
    with pytest.raises(auth.AuthError):
        auth.load_users(bad)


def test_load_users_not_a_list(tmp_path):
    """A top-level object (not an array) is rejected."""
    bad = tmp_path / "users.json"
    bad.write_text(json.dumps({"username": "x"}), encoding="utf-8")
    with pytest.raises(auth.AuthError):
        auth.load_users(bad)


# Authenticator end-to-end + throttling
def test_authenticate_valid(users_file):
    """Correct credentials authenticate successfully."""
    path, passwords = users_file
    a = auth.Authenticator(path)
    assert a.authenticate("carol", passwords["carol"]) is True


def test_authenticate_wrong_password(users_file):
    """A wrong password for a real user is rejected."""
    path, _ = users_file
    a = auth.Authenticator(path)
    assert a.authenticate("carol", "nope") is False


def test_authenticate_unknown_user(users_file):
    """An unknown username is rejected."""
    path, _ = users_file
    a = auth.Authenticator(path)
    assert a.authenticate("mallory", "whatever") is False


def test_throttle_locks_after_max_fails(users_file):
    """After max_fails failures the account is locked, blocking even the
    correct password until the lockout window elapses."""
    path, passwords = users_file
    a = auth.Authenticator(path, max_fails=3, lockout_seconds=60)
    for _ in range(3):
        assert a.authenticate("carol", "wrong") is False
    assert a.throttle.is_locked("carol") is True
    # Correct password is refused while locked.
    assert a.authenticate("carol", passwords["carol"]) is False


def test_throttle_success_resets(users_file):
    """A successful login clears the failure counter."""
    path, passwords = users_file
    a = auth.Authenticator(path, max_fails=3, lockout_seconds=60)
    a.authenticate("carol", "wrong")
    a.authenticate("carol", "wrong")
    assert a.authenticate("carol", passwords["carol"]) is True
    assert a.throttle.is_locked("carol") is False


def test_lockout_expires(users_file):
    """The lockout is temporary: it clears after lockout_seconds."""
    path, passwords = users_file
    a = auth.Authenticator(path, max_fails=1, lockout_seconds=0.3)
    assert a.authenticate("carol", "wrong") is False
    assert a.throttle.is_locked("carol") is True
    import time as _t
    _t.sleep(0.4)
    assert a.authenticate("carol", passwords["carol"]) is True


def test_predefined_users_load():
    """The shipped data/users.json loads with the three predefined users."""
    users = auth.load_users(ROOT / "data" / "users.json")
    assert {"alice", "bob", "eve"}.issubset(set(users))
