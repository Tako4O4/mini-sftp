import hashlib
import os
import socket
from threading import Thread

import pytest

from client.main import Client, Terminal, run_terminal
from server import main as server_main
from server.auth import create_user
from server.main import handle_client
from shared.protocol import (
    MAX_CHUNK_SIZE,
    receive_bytes,
    receive_message,
    send_message,
)


def _start_server(db_path):
    """Serve one connection on a socket pair.

    Returns (client socket, thread, errors), where errors collects any exception
    that escaped the session.
    """
    client_side, server_side = socket.socketpair()
    errors = []

    def run():
        try:
            with server_side:
                server_side.settimeout(3)
                handle_client(server_side, db_path)
        except (OSError, ValueError) as error:
            errors.append(error)

    thread = Thread(target=run, daemon=True)
    thread.start()
    client_side.settimeout(3)
    return client_side, thread, errors


def _finish(client_side, thread, errors):
    client_side.close()
    thread.join(timeout=5)
    assert not thread.is_alive(), "Server thread did not finish"
    return errors


def _login(sock, username="Alice", password="correct-password"):
    send_message(sock, {"command": "LOGIN", "username": username, "password": password})
    assert receive_message(sock)["status"] == "OK"


def _files_dir(db_path, username="Alice"):
    return db_path.parent / "files" / username


def _download(sock, name):
    """Run the DOWNLOAD exchange like a well-behaved client. Returns (header, data)."""
    send_message(sock, {"command": "DOWNLOAD", "name": name})
    header = receive_message(sock)
    if header["status"] != "READY":
        return header, None

    data = bytearray()
    while len(data) < header["size"]:
        data.extend(receive_bytes(sock))
    digest = hashlib.sha256(data).hexdigest()
    send_message(sock, {"status": "OK" if digest == header["sha256"] else "ERROR"})
    return header, bytes(data)


@pytest.fixture
def alice(tmp_path):
    db_path = tmp_path / "users.db"
    create_user("Alice", "correct-password", db_path)
    return db_path


def test_multi_chunk_download_matches_stored_file(alice):
    data = os.urandom(3 * MAX_CHUNK_SIZE + 77)
    _files_dir(alice).mkdir(parents=True)
    (_files_dir(alice) / "big.bin").write_bytes(data)
    sock, thread, errors = _start_server(alice)
    _login(sock)

    header, received = _download(sock, "big.bin")
    final = receive_message(sock)

    assert header["size"] == len(data)
    assert header["sha256"] == hashlib.sha256(data).hexdigest()
    assert received == data
    assert final == {"status": "OK", "response": "Downloaded 'big.bin'"}
    assert not _finish(sock, thread, errors)


def test_empty_file_download(alice):
    _files_dir(alice).mkdir(parents=True)
    (_files_dir(alice) / "empty.txt").write_bytes(b"")
    sock, thread, errors = _start_server(alice)
    _login(sock)

    header, received = _download(sock, "empty.txt")
    final = receive_message(sock)

    assert header["size"] == 0
    assert received == b""
    assert final["status"] == "OK"
    assert not _finish(sock, thread, errors)


def test_missing_file_returns_error_without_data(alice):
    sock, thread, errors = _start_server(alice)
    _login(sock)

    header, _ = _download(sock, "nothing.txt")

    assert header == {"status": "ERROR", "response": "No such file"}
    send_message(sock, {"command": "PING"})  # no data frames were sent
    assert receive_message(sock)["response"] == "PONG"
    assert not _finish(sock, thread, errors)


@pytest.mark.parametrize("name", ["../users.db", "a/b", ".hidden", "x.part", "", None])
def test_invalid_names_are_rejected(alice, name):
    sock, thread, errors = _start_server(alice)
    _login(sock)

    send_message(sock, {"command": "DOWNLOAD", "name": name})
    header = receive_message(sock)

    assert header["status"] == "ERROR"
    assert not _finish(sock, thread, errors)


def test_symlinks_are_not_downloadable(alice, tmp_path):
    _files_dir(alice).mkdir(parents=True)
    outside = tmp_path / "secret.txt"
    outside.write_bytes(b"not yours")
    (_files_dir(alice) / "link.txt").symlink_to(outside)
    sock, thread, errors = _start_server(alice)
    _login(sock)

    header, _ = _download(sock, "link.txt")

    assert header == {"status": "ERROR", "response": "No such file"}
    assert not _finish(sock, thread, errors)


def test_user_cannot_download_another_users_file(alice):
    create_user("Bob", "bob-password", alice)
    _files_dir(alice, "Bob").mkdir(parents=True)
    (_files_dir(alice, "Bob") / "private.txt").write_bytes(b"bob's")
    _files_dir(alice).mkdir(parents=True)
    sock, thread, errors = _start_server(alice)
    _login(sock)  # logged in as Alice

    header, _ = _download(sock, "private.txt")

    assert header == {"status": "ERROR", "response": "No such file"}
    assert not _finish(sock, thread, errors)


def test_download_requires_login(alice):
    sock, thread, errors = _start_server(alice)

    send_message(sock, {"command": "DOWNLOAD", "name": "a.txt"})
    assert receive_message(sock) == {"status": "ERROR", "response": "Login required"}
    assert not _finish(sock, thread, errors)


def test_client_reported_failure_is_logged_as_error(alice):
    _files_dir(alice).mkdir(parents=True)
    (_files_dir(alice) / "a.txt").write_bytes(b"data")
    sock, thread, errors = _start_server(alice)
    _login(sock)

    send_message(sock, {"command": "DOWNLOAD", "name": "a.txt"})
    header = receive_message(sock)
    receive_bytes(sock)  # the one data frame
    send_message(sock, {"status": "ERROR"})  # client says its check failed

    assert receive_message(sock)["status"] == "ERROR"
    assert header["status"] == "READY"
    assert not _finish(sock, thread, errors)


def test_file_removed_after_header_drops_connection(alice, monkeypatch):
    _files_dir(alice).mkdir(parents=True)
    path = _files_dir(alice) / "gone.txt"
    path.write_bytes(b"data")

    # Remove the file at the exact point between the header and the data.
    real_send = server_main.send_file_data

    def remove_then_send(connection, file_path, size):
        file_path.unlink()
        return real_send(connection, file_path, size)

    monkeypatch.setattr(server_main, "send_file_data", remove_then_send)
    sock, thread, errors = _start_server(alice)
    _login(sock)

    send_message(sock, {"command": "DOWNLOAD", "name": "gone.txt"})
    assert receive_message(sock)["status"] == "READY"

    errors = _finish(sock, thread, errors)
    assert len(errors) == 1 and isinstance(errors[0], FileNotFoundError)


def test_terminal_download_saves_verified_file(alice, tmp_path):
    _files_dir(alice).mkdir(parents=True)
    (_files_dir(alice) / "report.txt").write_bytes(b"quarterly numbers")
    destination = tmp_path / "saved.txt"

    client_side, server_side = socket.socketpair()
    thread = Thread(target=handle_client, args=(server_side, alice), daemon=True)
    thread.start()

    lines = iter(["LOGIN", "Alice", "DOWNLOAD", "report.txt", str(destination), "EXIT"])
    output = []
    term = Terminal(
        ask=lambda prompt: next(lines),
        ask_password=lambda prompt: "correct-password",
        write=output.append,
    )
    with client_side:
        client_side.settimeout(3)
        run_terminal(Client(client_side), term)
    thread.join(timeout=5)

    assert not thread.is_alive()
    assert destination.read_bytes() == b"quarterly numbers"
    assert not destination.with_name("saved.txt.part").exists()
    assert any("SHA-256 verified" in line for line in output)
