#TODO
import asyncio
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path

import asyncssh
import pytest

from client.client import SFTPClient, SFTPError

from secrets import token_urlsafe
from server.auth import hash_password


REPO_ROOT = Path(__file__).resolve().parents[1]
HOST = "127.0.0.1"
PORT = 2222
FLAG_PATH = "/projects/confidential/flag.txt"
FLAG_CONTENT = "FLAG{sftp_access_control_demo}\n"
PERMISSION_DENIED = 3


def wait_for_server(process, log_path):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            break
        try:
            with socket.create_connection((HOST, PORT), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)

    output = log_path.read_text(encoding="utf-8", errors="replace")
    pytest.fail(f"SFTP server did not start on {HOST}:{PORT}.\n{output}")


@pytest.fixture
def running_server(tmp_path):
    """Start the real server with an isolated jail and a temporary host key."""
    server_dir = tmp_path / "server"
    shutil.copytree(
        REPO_ROOT / "server",
        server_dir,
        ignore=shutil.ignore_patterns(
            "__pycache__", "sftp_root", "audit.jsonl", "ssh_host_ed25519_key*"
        ),
    )
    shutil.copytree(REPO_ROOT / "data", tmp_path / "data")

    passwords = {
        username: token_urlsafe(24)
        for username in ("alice", "bob", "eve")
    }

    users = [
        {"username": username, **hash_password(password)}
        for username, password in passwords.items()
    ]

    (tmp_path / "data" / "users.json").write_text(
        json.dumps(users, indent=2),
        encoding="utf-8",
    )

    jail = server_dir / "sftp_root"
    flag = jail / FLAG_PATH.lstrip("/")
    flag.parent.mkdir(parents=True)
    flag.write_text(FLAG_CONTENT, encoding="utf-8")
    (jail / "public").mkdir()

    key = asyncssh.generate_private_key("ssh-ed25519")
    key_path = server_dir / "ssh_host_ed25519_key"
    key_path.write_bytes(key.export_private_key())
    key_path.chmod(0o600)

    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_bytes(
        f"[{HOST}]:{PORT} ".encode() + key.export_public_key()
    )

    log_path = tmp_path / "server.log"
    with log_path.open("wb") as log:
        process = subprocess.Popen(
            [sys.executable, "-u", str(server_dir / "server.py")],
            cwd=tmp_path,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            wait_for_server(process, log_path)
            yield known_hosts, server_dir / "audit.jsonl", passwords
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


@asynccontextmanager
async def connect_client(username, password, known_hosts):
    async with asyncssh.connect(
        HOST,
        port=PORT,
        username=username,
        password=password,
        known_hosts=str(known_hosts),
        preferred_auth="password",
        connect_timeout=5,
    ) as connection:
        writer, reader, _ = await connection.open_session(
            subsystem="sftp", encoding=None
        )
        client = SFTPClient(writer, reader)
        await client.initialize()
        yield client


# def test_sftp_operations_and_flag_access(tmp_path):
#     """Verify normal transfers, authorized flag access, and audited denials."""
#     passwords = read_demo_passwords()
#
#     # Request the fixture after checking credentials so a missing variable
#     # fails before a server process starts.
#     run_flag_checks(tmp_path, passwords)
#
#
# def run_flag_checks(tmp_path, passwords):
#     # The test below supplies the server fixture through pytest.
#     raise RuntimeError("Use the fixture-based test shown below.")

def test_sftp_operations_and_flag_access(running_server, tmp_path, capsys):
    """Verify normal transfers, authorized flag access, and audited denials."""
    known_hosts, audit_path, passwords = running_server
    source = tmp_path / "source.bin"
    source.write_bytes(bytes(range(256)) * 300)

    async def exercise():
        async with connect_client("bob", passwords["bob"], known_hosts) as bob:
            await bob.pwd()
            await bob.mkdir("/projects/demo")
            await bob.ls("/projects")
            await bob.stat("/projects/demo")
            await bob.put(str(source), "/projects/demo/upload.bin")
            downloaded = tmp_path / "bob-download.bin"
            await bob.get("/projects/demo/upload.bin", str(downloaded))
            assert downloaded.read_bytes() == source.read_bytes()

            denied = tmp_path / "bob-flag.txt"
            with pytest.raises(SFTPError) as error:
                await bob.get(FLAG_PATH, str(denied))
            assert error.value.code == PERMISSION_DENIED
            assert not denied.exists()

        async with connect_client("eve", passwords["eve"], known_hosts) as eve:
            await eve.put(str(source), "/public/eve-upload.bin")
            denied = tmp_path / "eve-flag.txt"
            with pytest.raises(SFTPError) as error:
                await eve.get(FLAG_PATH, str(denied))
            assert error.value.code == PERMISSION_DENIED
            assert not denied.exists()

        async with connect_client("alice", passwords["alice"], known_hosts) as alice:
            downloaded = tmp_path / "alice-flag.txt"
            await alice.get(FLAG_PATH, str(downloaded))
            assert downloaded.read_text(encoding="utf-8") == FLAG_CONTENT

    asyncio.run(asyncio.wait_for(exercise(), timeout=20))

    output = capsys.readouterr().out.splitlines()
    assert "/" in output
    assert "demo" in output

    records = [
        json.loads(line)
        for line in audit_path.read_text(encoding="utf-8").splitlines()
    ]
    for user, expected in (("alice", True), ("bob", False), ("eve", False)):
        record = next(
            (
                entry for entry in records
                if entry["user"] == user
                and entry["op"] == "read"
                and entry["path"] == FLAG_PATH
                and entry["allowed"] is expected
            ),
            None,
        )
        assert record is not None, f"Missing flag-read audit record for {user}"
        assert record["reason"]
        assert record["timestamp"]
        print(json.dumps(record))