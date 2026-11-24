import getpass
import hashlib
import os
import socket
import sys
from collections.abc import Callable
from pathlib import Path

from shared.protocol import (
    MAX_CHUNK_SIZE,
    receive_bytes,
    receive_message,
    send_bytes,
    send_message,
)
from shared.tls import create_client_context

HOST = "127.0.0.1"
PORT = 5000
SERVER_NAME = "localhost"
REQUEST_TIMEOUT = 10

HELP_TEXT = """Commands:
  PING      check that the server responds
  REGISTER  create a new account (only when not logged in)
  LOGIN     log in with username and password
  LOGOUT    end the current login
  LIST      list your files (only when logged in)
  UPLOAD    send a local file to your account (only when logged in)
  DOWNLOAD  fetch one of your files and save it locally (only when logged in)
  HELP      show this list
  EXIT      close the client"""


class Terminal:
    """Input and output for the interactive client. Injectable for tests."""

    def __init__(
        self,
        ask: Callable[[str], str] = input,
        ask_password: Callable[[str], str] = getpass.getpass,
        write: Callable[[str], None] = print,
    ) -> None:
        self.ask = ask
        self.ask_password = ask_password
        self.write = write


class Client:
    """A connection to the server plus the username this terminal is logged in as."""

    def __init__(self, connection: socket.socket) -> None:
        self.connection = connection
        self.username: str | None = None

    def request(self, message: dict) -> dict:
        send_message(self.connection, message)
        return receive_message(self.connection)

    def send_file(self, path: Path, size: int) -> None:
        """Send exactly `size` bytes of a file as data frames."""
        sent = 0
        with path.open("rb") as file:
            while sent < size:
                chunk = file.read(min(MAX_CHUNK_SIZE, size - sent))
                if not chunk:
                    raise ValueError("File changed while uploading")
                send_bytes(self.connection, chunk)
                sent += len(chunk)

    def prompt(self) -> str:
        if self.username is None:
            return "mini-sftp> "
        return f"mini-sftp ({self.username})> "


def cmd_ping(client: Client, term: Terminal) -> None:
    response = client.request({"command": "PING"})
    term.write(response["response"])


def cmd_login(client: Client, term: Terminal) -> None:
    username = term.ask("Username: ").strip()
    password = term.ask_password("Password: ")

    response = client.request(
        {"command": "LOGIN", "username": username, "password": password}
    )
    if response["status"] == "OK":
        client.username = username
    term.write(response["response"])


def cmd_register(client: Client, term: Terminal) -> None:
    username = term.ask("New username: ").strip()
    password = term.ask_password("New password: ")
    confirmation = term.ask_password("Confirm password: ")

    if password != confirmation:
        term.write("Passwords do not match. Account not created.")
        return

    response = client.request(
        {"command": "REGISTER", "username": username, "password": password}
    )
    term.write(response["response"])


def cmd_logout(client: Client, term: Terminal) -> None:
    response = client.request({"command": "LOGOUT"})
    if response["status"] == "OK":
        client.username = None
    term.write(response["response"])


def cmd_list(client: Client, term: Terminal) -> None:
    response = client.request({"command": "LIST"})
    if response["status"] != "OK":
        term.write(response["response"])
        return

    files = response["files"]
    if not files:
        term.write("No files.")
        return
    for entry in files:
        term.write(f"{entry['size']:>12}  {entry['name']}")


def cmd_upload(client: Client, term: Terminal) -> None:
    local_path = Path(term.ask("Local file path: ").strip())
    if not local_path.is_file():
        term.write(f"Not a file: {local_path}")
        return

    size = local_path.stat().st_size
    digest = hashlib.sha256()
    with local_path.open("rb") as file:
        for chunk in iter(lambda: file.read(MAX_CHUNK_SIZE), b""):
            digest.update(chunk)
    checksum = digest.hexdigest()

    response = client.request(
        {
            "command": "UPLOAD",
            "name": local_path.name,
            "size": size,
            "sha256": checksum,
        }
    )
    if response["status"] != "READY":
        term.write(response["response"])
        return

    client.send_file(local_path, size)
    response = receive_message(client.connection)

    if response["status"] != "OK":
        term.write(response["response"])
    elif response.get("sha256") != checksum:
        term.write("Server checksum does not match; the upload may be corrupt.")
    else:
        term.write(f"Uploaded {local_path.name} ({size} bytes), SHA-256 verified.")


def cmd_download(client: Client, term: Terminal) -> None:
    name = term.ask("File name to download: ").strip()
    response = client.request({"command": "DOWNLOAD", "name": name})
    if response["status"] != "READY":
        term.write(response["response"])
        return

    size = response["size"]
    expected = response["sha256"]
    destination = Path(term.ask(f"Save as [{name}]: ").strip() or name)
    part_path = destination.with_name(destination.name + ".part")

    digest = hashlib.sha256()
    received = 0
    try:
        with part_path.open("wb") as part:
            while received < size:
                chunk = receive_bytes(client.connection)
                if not chunk or received + len(chunk) > size:
                    raise ValueError("Download data does not match the declared size")
                part.write(chunk)
                digest.update(chunk)
                received += len(chunk)
    except BaseException:
        part_path.unlink(missing_ok=True)
        raise

    if digest.hexdigest() != expected:
        part_path.unlink(missing_ok=True)
        send_message(client.connection, {"status": "ERROR"})
        receive_message(client.connection)
        term.write("Checksum mismatch; download discarded.")
        return

    os.replace(part_path, destination)
    send_message(client.connection, {"status": "OK"})
    receive_message(client.connection)
    term.write(f"Downloaded {name} ({size} bytes) to {destination}, SHA-256 verified.")


COMMANDS = {
    "PING": cmd_ping,
    "LOGIN": cmd_login,
    "REGISTER": cmd_register,
    "LOGOUT": cmd_logout,
    "LIST": cmd_list,
    "UPLOAD": cmd_upload,
    "DOWNLOAD": cmd_download,
}


def run_terminal(client: Client, term: Terminal) -> int:
    """Read commands until EXIT, end of input, or the connection is lost."""
    term.write("Connected securely. Type HELP for a list of commands.")

    while True:
        try:
            line = term.ask(client.prompt())
        except EOFError:
            return 0

        name = line.strip().upper()
        if not name:
            continue
        if name in ("EXIT", "QUIT"):
            return 0
        if name == "HELP":
            term.write(HELP_TEXT)
            continue

        handler = COMMANDS.get(name)
        if handler is None:
            term.write(f"Unknown command: {name}. Type HELP for a list of commands.")
            continue

        try:
            handler(client, term)
        except (ConnectionError, OSError, ValueError) as error:
            term.write(f"Connection to server lost: {error}")
            return 1


def main() -> int:
    tls_context = create_client_context()

    try:
        raw_connection = socket.create_connection((HOST, PORT), timeout=REQUEST_TIMEOUT)
    except OSError as error:
        print(f"Could not connect to {HOST}:{PORT}: {error}")
        return 1

    with raw_connection:
        with tls_context.wrap_socket(
            raw_connection,
            server_hostname=SERVER_NAME,
        ) as connection:
            return run_terminal(Client(connection), Terminal())


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(0)
