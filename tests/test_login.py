import socket
from threading import Thread

from client.main import Client, Terminal, run_terminal
from server.auth import create_user
from server.main import handle_client


def _serve(connection_side, db_path, errors):
    try:
        with connection_side:
            connection_side.settimeout(3)
            handle_client(connection_side, db_path)
    except OSError as error:
        errors.append(error)


def _run_session(db_path, lines, passwords):
    """Drive the interactive terminal against a real server loop over a socket pair."""
    client_side, server_side = socket.socketpair()
    errors = []
    thread = Thread(target=_serve, args=(server_side, db_path, errors))
    thread.start()

    output = []
    lines = iter(lines)
    passwords = iter(passwords)
    term = Terminal(
        ask=lambda prompt: next(lines),
        ask_password=lambda prompt: next(passwords),
        write=output.append,
    )

    try:
        with client_side:
            client_side.settimeout(3)
            client = Client(client_side)
            exit_code = run_terminal(client, term)
            final_user = client.username
    finally:
        thread.join(timeout=5)

    assert not thread.is_alive(), "Server thread did not finish"
    assert not errors, f"Server errors: {errors}"
    return exit_code, final_user, output


def test_register_login_ping_logout(tmp_path):
    exit_code, final_user, output = _run_session(
        tmp_path / "users.db",
        lines=[
            "REGISTER",
            "Alice",
            "LOGIN",
            "Alice",
            "PING",
            "LOGOUT",
            "EXIT",
        ],
        passwords=[
            "correct-password",  # register
            "correct-password",  # register confirmation
            "correct-password",  # login
        ],
    )

    assert exit_code == 0
    assert final_user is None
    assert "Account 'Alice' created. You can now LOGIN." in output
    assert "Logged in as Alice" in output
    assert "PONG" in output
    assert "Logged out" in output


def test_register_with_mismatched_passwords_sends_nothing(tmp_path):
    db_path = tmp_path / "users.db"
    _, _, output = _run_session(
        db_path,
        lines=["REGISTER", "Alice", "EXIT"],
        passwords=["first-password", "other-password"],
    )

    assert "Passwords do not match. Account not created." in output
    # Nothing was created, so the account cannot log in.
    _, final_user, output = _run_session(
        db_path,
        lines=["LOGIN", "Alice", "EXIT"],
        passwords=["first-password"],
    )
    assert final_user is None
    assert "Invalid username or password" in output


def test_bad_login_keeps_terminal_usable(tmp_path):
    db_path = tmp_path / "users.db"
    _run_session(
        db_path,
        lines=["REGISTER", "Alice", "EXIT"],
        passwords=["correct-password", "correct-password"],
    )

    exit_code, final_user, output = _run_session(
        db_path,
        lines=["LOGIN", "Alice", "PING", "EXIT"],
        passwords=["wrong-password"],
    )

    assert exit_code == 0
    assert final_user is None
    assert "Invalid username or password" in output
    assert "PONG" in output


def test_unknown_command_is_handled_locally(tmp_path):
    _, _, output = _run_session(
        tmp_path / "users.db",
        lines=["FLY", "EXIT"],
        passwords=[],
    )
    assert "Unknown command: FLY. Type HELP for a list of commands." in output


def test_list_in_terminal_shows_files(tmp_path):
    db_path = tmp_path / "users.db"
    create_user("Alice", "correct-password", db_path)
    files_dir = db_path.parent / "files" / "Alice"
    files_dir.mkdir(parents=True)
    (files_dir / "notes.txt").write_bytes(b"hello")

    _, _, output = _run_session(
        db_path,
        lines=["LOGIN", "Alice", "LIST", "EXIT"],
        passwords=["correct-password"],
    )

    assert "           5  notes.txt" in output


def test_list_in_terminal_when_empty(tmp_path):
    db_path = tmp_path / "users.db"
    create_user("Alice", "correct-password", db_path)

    _, _, output = _run_session(
        db_path,
        lines=["LOGIN", "Alice", "LIST", "EXIT"],
        passwords=["correct-password"],
    )

    assert "No files." in output
