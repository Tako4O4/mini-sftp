import getpass
import socket
import sys
from collections.abc import Callable

from shared.protocol import receive_message, send_message
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


COMMANDS = {
    "PING": cmd_ping,
    "LOGIN": cmd_login,
    "REGISTER": cmd_register,
    "LOGOUT": cmd_logout,
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
