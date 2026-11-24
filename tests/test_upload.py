import hashlib
import os
import socket
from threading import Thread

import pytest

from client.main import Client, Terminal, run_terminal
from server import storage
from server.auth import create_user
from server.main import handle_client
from shared.protocol import MAX_CHUNK_SIZE, receive_message, send_bytes, send_message


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


def _header(name, data, **overrides):
    header = {
        "command": "UPLOAD",
        "name": name,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    header.update(overrides)
    return header


def _send_data(sock, data):
    for start in range(0, len(data), MAX_CHUNK_SIZE):
        send_bytes(sock, data[start : start + MAX_CHUNK_SIZE])


def _files_dir(db_path, username="Alice"):
    return db_path.parent / "files" / username


@pytest.fixture
def alice(tmp_path):
    db_path = tmp_path / "users.db"
    create_user("Alice", "correct-password", db_path)
    return db_path


def test_multi_chunk_upload_is_stored_and_verified(alice):
    data = os.urandom(3 * MAX_CHUNK_SIZE + 123)
    sock, thread, errors = _start_server(alice)
    _login(sock)

    send_message(sock, _header("big.bin", data))
    assert receive_message(sock)["status"] == "READY"
    _send_data(sock, data)
    response = receive_message(sock)

    assert response["status"] == "OK"
    assert response["sha256"] == hashlib.sha256(data).hexdigest()
    assert (_files_dir(alice) / "big.bin").read_bytes() == data
    assert not (_files_dir(alice) / "big.bin.part").exists()
    assert not _finish(sock, thread, errors)


def test_empty_file_upload(alice):
    sock, thread, errors = _start_server(alice)
    _login(sock)

    send_message(sock, _header("empty.txt", b""))
    assert receive_message(sock)["status"] == "READY"
    response = receive_message(sock)

    assert response["status"] == "OK"
    assert (_files_dir(alice) / "empty.txt").read_bytes() == b""
    assert not _finish(sock, thread, errors)


def test_checksum_mismatch_discards_data_and_keeps_connection(alice):
    data = b"real contents"
    sock, thread, errors = _start_server(alice)
    _login(sock)

    send_message(sock, _header("doc.txt", data, sha256="0" * 64))
    assert receive_message(sock)["status"] == "READY"
    _send_data(sock, data)
    response = receive_message(sock)

    assert response == {
        "status": "ERROR",
        "response": "Checksum mismatch; upload discarded",
    }
    assert not (_files_dir(alice) / "doc.txt").exists()
    assert not (_files_dir(alice) / "doc.txt.part").exists()

    # The connection is still usable after a checksum failure.
    send_message(sock, {"command": "PING"})
    assert receive_message(sock)["response"] == "PONG"
    assert not _finish(sock, thread, errors)


@pytest.mark.parametrize(
    "name",
    ["../escape.txt", "sub/file.txt", "back\\slash", ".hidden", "x.part", "", "a\nb"],
)
def test_bad_file_names_are_rejected_before_any_data(alice, name):
    data = b"payload"
    sock, thread, errors = _start_server(alice)
    _login(sock)

    send_message(sock, _header(name, data))
    response = receive_message(sock)

    assert response["status"] == "ERROR"
    assert not (alice.parent / "escape.txt").exists()
    send_message(sock, {"command": "PING"})  # no data was expected, so PING works
    assert receive_message(sock)["response"] == "PONG"
    assert not _finish(sock, thread, errors)


@pytest.mark.parametrize(
    "overrides",
    [
        {"size": -1},
        {"size": "10"},
        {"size": True},
        {"sha256": "ABCDEF"},
        {"sha256": 123},
    ],
)
def test_bad_header_fields_are_rejected(alice, overrides):
    sock, thread, errors = _start_server(alice)
    _login(sock)

    send_message(sock, _header("ok.txt", b"data", **overrides))
    assert receive_message(sock)["status"] == "ERROR"
    assert not _finish(sock, thread, errors)


def test_size_limit_is_enforced(alice, monkeypatch):
    monkeypatch.setattr(storage, "MAX_UPLOAD_SIZE", 10)
    sock, thread, errors = _start_server(alice)
    _login(sock)

    send_message(sock, _header("big.txt", b"x" * 11))
    response = receive_message(sock)

    assert response == {"status": "ERROR", "response": "File size must be 0-10 bytes"}
    assert not _finish(sock, thread, errors)


def test_upload_requires_login(alice):
    sock, thread, errors = _start_server(alice)

    send_message(sock, _header("ok.txt", b"data"))
    assert receive_message(sock) == {"status": "ERROR", "response": "Login required"}
    assert not _finish(sock, thread, errors)


def test_protocol_violation_removes_partial_file(alice):
    sock, thread, errors = _start_server(alice)
    _login(sock)

    send_message(sock, _header("short.txt", b"0123456789"))  # declares 10 bytes
    assert receive_message(sock)["status"] == "READY"
    send_bytes(sock, b"0123456789ABCDEFGHIJ")  # sends 20

    errors = _finish(sock, thread, errors)
    assert len(errors) == 1 and isinstance(errors[0], ValueError)
    assert not (_files_dir(alice) / "short.txt.part").exists()
    assert not (_files_dir(alice) / "short.txt").exists()


def test_disconnect_mid_upload_removes_partial_file(alice):
    sock, thread, errors = _start_server(alice)
    _login(sock)

    send_message(sock, _header("cut.txt", b"x" * 100))
    assert receive_message(sock)["status"] == "READY"
    send_bytes(sock, b"x" * 10)  # then the client disappears

    errors = _finish(sock, thread, errors)
    assert len(errors) == 1 and isinstance(errors[0], ConnectionError)
    assert not (_files_dir(alice) / "cut.txt.part").exists()
    assert not (_files_dir(alice) / "cut.txt").exists()


def test_upload_overwrites_existing_file(alice):
    sock, thread, errors = _start_server(alice)
    _login(sock)

    for data in (b"first version", b"second version"):
        send_message(sock, _header("note.txt", data))
        assert receive_message(sock)["status"] == "READY"
        _send_data(sock, data)
        assert receive_message(sock)["status"] == "OK"

    assert (_files_dir(alice) / "note.txt").read_bytes() == b"second version"
    assert not _finish(sock, thread, errors)


def test_failed_rename_removes_partial_file(alice):
    # A directory with the same name makes the final rename fail.
    (_files_dir(alice) / "docs").mkdir(parents=True)
    sock, thread, errors = _start_server(alice)
    _login(sock)

    send_message(sock, _header("docs", b"data"))
    assert receive_message(sock)["status"] == "READY"
    _send_data(sock, b"data")

    errors = _finish(sock, thread, errors)
    assert len(errors) == 1 and isinstance(errors[0], OSError)
    assert not (_files_dir(alice) / "docs.part").exists()


def test_terminal_upload_reports_verified_checksum(alice, tmp_path):
    local_file = tmp_path / "hello.txt"
    local_file.write_bytes(b"hello from the terminal")

    client_side, server_side = socket.socketpair()
    thread = Thread(target=handle_client, args=(server_side, alice), daemon=True)
    thread.start()

    lines = iter(["LOGIN", "Alice", "UPLOAD", str(local_file), "LIST", "EXIT"])
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
    assert "Uploaded hello.txt (23 bytes), SHA-256 verified." in output
    assert any("hello.txt" in line and "23" in line for line in output)
