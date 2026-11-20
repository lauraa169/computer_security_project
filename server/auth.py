"""
Password authentication for the SFTP server.

Passwords are stored as salted scrypt hashes in data/users.json (stdlib only).
This module loads that static user set at startup, verifies passwords in
constant time, and applies a per-user lockout after repeated failures.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict


# scrypt parameters (defaults used when creating NEW hashes)
DEFAULT_N = 16384      # CPU/memory cost (must be a power of 2)
DEFAULT_R = 8          # block size
DEFAULT_P = 1          # parallelization
DEFAULT_DKLEN = 32     # derived key length in bytes
DEFAULT_SALT_BYTES = 16


class AuthError(Exception):
    """Raised for fatal authentication-subsystem errors (e.g. bad user file)."""


# Hashing / verification primitives
def _scrypt(password: str, salt: bytes, n: int, r: int, p: int, dklen: int) -> bytes:
    """Derive a key from a password using scrypt. maxmem is raised so larger
    n values do not hit the stdlib default memory ceiling."""
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=n,
        r=r,
        p=p,
        dklen=dklen,
        maxmem=132 * 1024 * 1024,
    )


def hash_password(
    password: str,
    n: int = DEFAULT_N,
    r: int = DEFAULT_R,
    p: int = DEFAULT_P,
    dklen: int = DEFAULT_DKLEN,
) -> dict:
    """Create a fresh salted scrypt record for a plaintext password.

    Returns a dict with base64 salt/hash and the KDF parameters — the exact
    shape stored in data/users.json (minus the username)."""
    salt = os.urandom(DEFAULT_SALT_BYTES)
    derived = _scrypt(password, salt, n, r, p, dklen)
    return {
        "salt": base64.b64encode(salt).decode("ascii"),
        "password_hash": base64.b64encode(derived).decode("ascii"),
        "n": n,
        "r": r,
        "p": p,
        "dklen": dklen,
    }


def verify_password(password: str, record: dict) -> bool:
    """Constant-time verification of a password against a stored user record.

    `record` must contain salt, password_hash, n, r, p, dklen.
    Returns False (never raises) on a malformed record so a single bad row
    cannot crash a login attempt."""
    try:
        salt = base64.b64decode(record["salt"])
        expected = base64.b64decode(record["password_hash"])
        derived = _scrypt(
            password,
            salt,
            int(record["n"]),
            int(record["r"]),
            int(record["p"]),
            int(record["dklen"]),
        )
    except (KeyError, ValueError, TypeError):
        return False
    return hmac.compare_digest(derived, expected)


# A fixed dummy record used to equalise timing for unknown usernames.
_DUMMY_RECORD = hash_password("timing-equalisation-placeholder")


# User dataset loading (static, at startup)
_REQUIRED_FIELDS = ("username", "salt", "password_hash", "n", "r", "p", "dklen")


def load_users(path: str | Path = "data/users.json") -> Dict[str, dict]:
    """Load and validate the predefined users from users.json.

    Returns a dict username -> record. Raises AuthError with a readable message
    on a missing file, invalid JSON, or a malformed/duplicate user entry, so
    the server fails cleanly at startup (acceptance criteria)."""
    path = Path(path)
    if not path.is_file():
        raise AuthError(f"users file not found: '{path}'")

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        raise AuthError(f"users file '{path}' is not valid JSON: {exc}")

    if not isinstance(data, list):
        raise AuthError(f"users file '{path}' must contain a JSON array of users")

    users: Dict[str, dict] = {}
    for i, entry in enumerate(data):
        if not isinstance(entry, dict):
            raise AuthError(f"user entry #{i} is not a JSON object")
        missing = [k for k in _REQUIRED_FIELDS if k not in entry]
        if missing:
            raise AuthError(
                f"user entry #{i} is missing field(s): {', '.join(missing)}"
            )
        username = entry["username"]
        if not isinstance(username, str) or not username:
            raise AuthError(f"user entry #{i} has an invalid username")
        if username in users:
            raise AuthError(f"duplicate username in users file: '{username}'")
        # Validate base64 + integer params up front so a bad row is caught at
        # startup rather than at first login.
        try:
            base64.b64decode(entry["salt"])
            base64.b64decode(entry["password_hash"])
            int(entry["n"]); int(entry["r"]); int(entry["p"]); int(entry["dklen"])
        except (ValueError, TypeError) as exc:
            raise AuthError(f"user '{username}' has malformed hash fields: {exc}")
        users[username] = entry

    if not users:
        raise AuthError(f"users file '{path}' contains no users")

    print(f"[auth] Loaded {len(users)} users from {path}: {', '.join(users)}")
    return users


# Login throttling / lockout
@dataclass
class _Attempts:
    fails: int = 0
    locked_until: float = 0.0


@dataclass
class LoginThrottle:
    """Per-username login rate-limiter with temporary lockout.

    After `max_fails` consecutive failed attempts the account is locked for
    `lockout_seconds`. A successful login resets the counter. This bounds
    online brute-force / password-spraying against the static user set."""

    max_fails: int = 5
    lockout_seconds: float = 30.0
    _state: Dict[str, _Attempts] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def _now(self) -> float:
        return time.monotonic()

    def is_locked(self, username: str) -> bool:
        with self._lock:
            st = self._state.get(username)
            if st is None:
                return False
            return self._now() < st.locked_until

    def seconds_remaining(self, username: str) -> float:
        with self._lock:
            st = self._state.get(username)
            if st is None:
                return 0.0
            return max(0.0, st.locked_until - self._now())

    def record_failure(self, username: str) -> None:
        with self._lock:
            st = self._state.setdefault(username, _Attempts())
            st.fails += 1
            if st.fails >= self.max_fails:
                st.locked_until = self._now() + self.lockout_seconds

    def record_success(self, username: str) -> None:
        with self._lock:
            self._state.pop(username, None)


# Authenticator — ties the dataset + throttle + verification together
class Authenticator:
    """Front door for password authentication used by the SSH server's
    password-auth callback."""

    def __init__(
        self,
        users_path: str | Path = "data/users.json",
        max_fails: int = 5,
        lockout_seconds: float = 30.0,
    ):
        self.users = load_users(users_path)
        self.throttle = LoginThrottle(max_fails=max_fails, lockout_seconds=lockout_seconds)

    def authenticate(self, username: str, password: str) -> bool:
        """Return True iff the username exists, is not locked out, and the
        password verifies. Records the attempt against the throttle.

        Timing is equalised for unknown users to resist account enumeration.
        """
        if self.throttle.is_locked(username):
            return False

        record = self.users.get(username)
        if record is None:
            # Perform a dummy scrypt so timing does not reveal non-existence.
            verify_password(password, _DUMMY_RECORD)
            self.throttle.record_failure(username)
            return False

        if verify_password(password, record):
            self.throttle.record_success(username)
            return True

        self.throttle.record_failure(username)
        return False
