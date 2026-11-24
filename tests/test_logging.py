import socket
from threading import Thread

from server.auth import create_user
from server.main import Session, format_endpoint, handle_client, source_label
from shared.protocol import receive_message, send_message

PORT = 51242
ADDRESS = ("127.0.0.1", PORT)
ENDPOINT = f"127.0.0.1:{PORT}"


def _run_requests(db_path, requests, capsys):
    """Run one session and return only the log lines for this session's port.

    Filtering by port keeps the result stable when other tests' background
    server threads print their own lines while this test is capturing output.
    """
    client_side, server_side = socket.socketpair()
    thread = Thread(
        target=handle_client,
        args=(server_side, db_path, ADDRESS),
        daemon=True,
    )
    thread.start()
    with client_side:
        client_side.settimeout(3)
        for request in requests:
            send_message(client_side, request)
            receive_message(client_side)
    thread.join(timeout=5)
    assert not thread.is_alive()

    output = capsys.readouterr().out.splitlines()
    return [line for line in output if str(PORT) in line]


def test_format_endpoint_brackets_ipv6():
    assert format_endpoint(("127.0.0.1", 5000)) == "127.0.0.1:5000"
    assert format_endpoint(("::1", 5000, 0, 0)) == "[::1]:5000"
    assert format_endpoint(None) == "unknown"


def test_source_label_before_and_after_login():
    assert source_label(ADDRESS, Session()) == ENDPOINT
    assert source_label(ADDRESS, Session(username="Alice")) == f"Alice ({ENDPOINT})"


def test_failed_login_and_register_log_attempted_username(tmp_path, capsys):
    db_path = tmp_path / "users.db"
    create_user("Alice", "correct-password", db_path)

    lines = _run_requests(
        db_path,
        [
            {"command": "LOGIN", "username": "mallory", "password": "guess"},
            {"command": "REGISTER", "username": "Bob", "password": "bob-password"},
        ],
        capsys,
    )

    assert lines == [
        f"Command LOGIN from {ENDPOINT} for user 'mallory' -> ERROR",
        f"Command REGISTER from {ENDPOINT} for user 'Bob' -> OK",
        f"Client {ENDPOINT} disconnected",
    ]


def test_newline_in_username_cannot_forge_log_lines(tmp_path, capsys):
    forged = "bob\nCommand LOGIN from 1 for user 'admin' -> OK"

    lines = _run_requests(
        tmp_path / "users.db",
        [{"command": "LOGIN", "username": forged, "password": "x"}],
        capsys,
    )

    # Exactly one command line and one disconnect line for this session.
    assert len(lines) == 2
    assert lines[0].startswith(f"Command LOGIN from {ENDPOINT} for user ")
    assert "\\n" in lines[0]  # the newline is shown escaped
    assert lines[0].endswith("-> ERROR")


def test_unknown_command_name_is_escaped(tmp_path, capsys):
    lines = _run_requests(
        tmp_path / "users.db",
        [{"command": "PING\nCommand LOGIN from 1 -> OK"}],
        capsys,
    )

    assert len(lines) == 2
    assert lines[0].startswith(
        f"Command 'PING\\nCommand LOGIN from 1 -> OK' from {ENDPOINT}"
    )


def test_log_lines_name_source_and_user(tmp_path, capsys):
    db_path = tmp_path / "users.db"
    create_user("Alice", "correct-password", db_path)

    lines = _run_requests(
        db_path,
        [
            {"command": "PING"},
            {"command": "LOGIN", "username": "Alice", "password": "correct-password"},
            {"command": "PING"},
        ],
        capsys,
    )

    assert lines == [
        f"Command PING from {ENDPOINT} -> OK",
        f"Command LOGIN from Alice ({ENDPOINT}) for user 'Alice' -> OK",
        f"Command PING from Alice ({ENDPOINT}) -> OK",
        f"Client Alice ({ENDPOINT}) disconnected",
    ]
