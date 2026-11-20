
import argparse
import asyncio
from contextlib import asynccontextmanager, suppress
from getpass import getpass
from pathlib import Path, PurePosixPath
import shlex
import stat
import struct
import sys
from tempfile import NamedTemporaryFile

import asyncssh

INIT, VERSION, OPEN, CLOSE, READ, WRITE = range(1, 7)
OPENDIR, READDIR, MKDIR, REALPATH, STAT = 11, 12, 14, 16, 17
STATUS, HANDLE, DATA, NAME, ATTRS = range(101, 106)
OK, EOF = 0, 1
OPEN_READ = 0x01
OPEN_WRITE_CREATE_TRUNCATE = 0x02 | 0x08 | 0x10
CHUNK_SIZE = 32 * 1024
MAX_PACKET_SIZE = 1024 * 1024
STATUS_NAMES = {
    1: "End of file",
    2: "No such file",
    3: "Permission denied",
    4: "Server failure",
    5: "Bad message",
    8: "Operation unsupported",
}


class ProtocolError(Exception):
    """The session received a reply it cannot safely use."""


class SFTPError(Exception):
    """The server rejected a single request."""

    def __init__(self, code, detail):
        self.code = code
        label = STATUS_NAMES.get(code, f"SFTP status {code}")
        super().__init__(f"{label} ({detail})" if detail else label)


def display(data):
    """Keep control characters in remote names and messages out of the terminal."""
    return "".join(char if char.isprintable() else ascii(char)[1:-1]
                   for char in data.decode("utf-8", errors="backslashreplace"))


def string(value):
    return struct.pack(">I", len(value)) + value


def remote_path(path):
    return string(path.encode("utf-8"))


class Reply:
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def take(self, size):
        end = self.offset + size
        if end > len(self.data):
            raise ProtocolError("Truncated SFTP reply")
        value = self.data[self.offset:end]
        self.offset = end
        return value

    def u32(self):
        return struct.unpack(">I", self.take(4))[0]

    def u64(self):
        return struct.unpack(">Q", self.take(8))[0]

    def string(self):
        return self.take(self.u32())

    def attributes(self):
        flags = self.u32()
        attributes = {}
        if flags & 0x01:
            attributes["size"] = self.u64()
        if flags & 0x02:
            attributes["uid"], attributes["gid"] = self.u32(), self.u32()
        if flags & 0x04:
            attributes["permissions"] = stat.filemode(self.u32())
        if flags & 0x08:
            attributes["atime"], attributes["mtime"] = self.u32(), self.u32()
        if flags & 0x80000000:
            for _ in range(self.u32()):
                self.string()
                self.string()
        return attributes

    def names(self):
        for _ in range(self.u32()):
            name = self.string()
            self.string()  # SFTP v3 also includes a display-oriented long name.
            yield display(name), self.attributes()


class SFTPClient:
    def __init__(self, writer, reader):
        self.writer = writer
        self.reader = reader
        self.request_id = 0

    async def exchange(self, kind, payload):
        size = 1 + len(payload)
        if size > MAX_PACKET_SIZE:
            raise ValueError("SFTP request is too large")
        self.writer.write(struct.pack(">IB", size, kind) + payload)
        await self.writer.drain()

        size = struct.unpack(">I", await self.reader.readexactly(4))[0]
        if not 1 <= size <= MAX_PACKET_SIZE:
            raise ProtocolError(f"Invalid SFTP packet length {size}")
        body = await self.reader.readexactly(size)
        return body[0], Reply(body[1:])

    async def initialize(self):
        kind, reply = await self.exchange(INIT, struct.pack(">I", 3))
        if kind != VERSION or reply.u32() != 3:
            raise ProtocolError("The server did not negotiate SFTP version 3")

    async def request(self, kind, payload, expected):
        self.request_id = (self.request_id + 1) & 0xFFFFFFFF
        reply_kind, reply = await self.exchange(
            kind, struct.pack(">I", self.request_id) + payload
        )
        if reply.u32() != self.request_id:
            raise ProtocolError("SFTP response request ID does not match")
        if reply_kind == STATUS:
            code = reply.u32()
            message = display(reply.string())
            reply.string()  # Language tag.
            if code != OK:
                raise SFTPError(code, message)
        if reply_kind != expected:
            raise ProtocolError(f"Expected SFTP reply {expected}, received {reply_kind}")
        return reply

    @asynccontextmanager
    async def handle(self, kind, payload):
        reply = await self.request(kind, payload, HANDLE)
        encoded_handle = string(reply.string())
        try:
            yield encoded_handle
        except (ProtocolError, asyncio.IncompleteReadError, asyncssh.Error):
            # The SSH connection closes the channel after a fatal protocol error.
            raise
        except BaseException:
            with suppress(SFTPError, OSError, ProtocolError, asyncio.IncompleteReadError,
                          asyncssh.Error):
                await self.request(CLOSE, encoded_handle, STATUS)
            raise
        else:
            await self.request(CLOSE, encoded_handle, STATUS)

    async def pwd(self):
        reply = await self.request(REALPATH, remote_path("."), NAME)
        names = list(reply.names())
        if len(names) != 1:
            raise ProtocolError("REALPATH must return one path")
        print(names[0][0])

    async def ls(self, path="."):
        async with self.handle(OPENDIR, remote_path(path)) as handle:
            while True:
                try:
                    reply = await self.request(READDIR, handle, NAME)
                except SFTPError as error:
                    if error.code == EOF:
                        break
                    raise
                names = list(reply.names())
                if not names:
                    raise ProtocolError("READDIR returned an empty name list")
                for name, _ in names:
                    print(name)

    async def mkdir(self, path):
        await self.request(MKDIR, remote_path(path) + struct.pack(">I", 0), STATUS)

    async def stat(self, path):
        reply = await self.request(STAT, remote_path(path), ATTRS)
        attributes = reply.attributes()
        print(" ".join(f"{key}={value}" for key, value in attributes.items())
              or "No attributes returned")

    async def get(self, remote, local=None):
        name = PurePosixPath(remote).name
        if local is None and (name in ("", ".", "..") or chr(92) in name or ":" in name):
            raise ValueError("Specify a local filename for this remote path")
        destination = Path(local if local is not None else name).expanduser()
        temporary_path = None
        try:
            async with self.handle(OPEN, remote_path(remote) + struct.pack(">II", OPEN_READ, 0)) as handle:
                with NamedTemporaryFile(mode="wb", dir=destination.parent, delete=False) as output:
                    temporary_path = Path(output.name)
                    offset = 0
                    while True:
                        try:
                            reply = await self.request(
                                READ, handle + struct.pack(">QI", offset, CHUNK_SIZE), DATA
                            )
                        except SFTPError as error:
                            if error.code == EOF:
                                break
                            raise
                        data = reply.string()
                        if not 1 <= len(data) <= CHUNK_SIZE:
                            raise ProtocolError("Invalid SFTP read length")
                        output.write(data)
                        offset += len(data)
            temporary_path.replace(destination)
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)
        print(f"Downloaded {offset} bytes to {destination}")

    async def put(self, local, remote):
        payload = remote_path(remote) + struct.pack(">II", OPEN_WRITE_CREATE_TRUNCATE, 0)
        offset = 0
        with Path(local).expanduser().open("rb") as source:
            async with self.handle(OPEN, payload) as handle:
                while chunk := source.read(CHUNK_SIZE):
                    await self.request(WRITE, handle + struct.pack(">Q", offset) + string(chunk), STATUS)
                    offset += len(chunk)
        print(f"Uploaded {offset} bytes")


async def prompt(client):
    commands = {
        "pwd": (client.pwd, 0, 0, "pwd"),
        "ls": (client.ls, 0, 1, "ls [path]"),
        "mkdir": (client.mkdir, 1, 1, "mkdir <path>"),
        "stat": (client.stat, 1, 1, "stat <path>"),
        "get": (client.get, 1, 2, "get <remote> [local]"),
        "put": (client.put, 2, 2, "put <local> <remote>"),
    }
    while True:
        try:
            line = input("sftp> ")
        except EOFError:
            break
        try:
            lexer = shlex.shlex(line, posix=True)
            lexer.whitespace_split = True
            lexer.commenters = ""
            lexer.escape = ""  # Preserve backslashes in local Windows paths.
            words = list(lexer)
            if not words:
                continue
            command, *args = words
            if command in {"quit", "help"}:
                if args:
                    raise ValueError(f"Usage: {command}")
                if command == "quit":
                    break
                print("\n".join(item[3] for item in commands.values()))
                print("help\nquit")
                continue
            if command not in commands:
                raise ValueError("Unknown command. Type help for available commands.")
            run, minimum, maximum, usage = commands[command]
            if not minimum <= len(args) <= maximum:
                raise ValueError(f"Usage: {usage}")
            await run(*args)
        except (SFTPError, ValueError, OSError) as error:
            print(f"Error: {error}", file=sys.stderr)


async def run_client(args, password):
    async with asyncssh.connect(
        args.host, port=args.port, username=args.username, password=password,
        known_hosts=str(args.known_hosts.expanduser()), preferred_auth="password",
        connect_timeout=15,
    ) as connection:
        writer, reader, _ = await connection.open_session(subsystem="sftp", encoding=None)
        client = SFTPClient(writer, reader)
        await client.initialize()
        print("Connected using SFTP v3. Type help for commands.")
        await prompt(client)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2222)
    parser.add_argument("--username", required=True)
    parser.add_argument("--known-hosts", type=Path, default=Path("~/.ssh/known_hosts"))
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    try:
        password = getpass(f"Password for {args.username}: ")
        asyncio.run(run_client(args, password))
    except KeyboardInterrupt:
        print()
        return 130
    except asyncio.IncompleteReadError:
        print("Error: The server closed the SFTP session during a reply.", file=sys.stderr)
        return 1
    except (asyncssh.Error, ProtocolError, OSError, ValueError, EOFError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
