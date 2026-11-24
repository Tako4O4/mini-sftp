import pytest

from server import storage
from server.auth import create_user
from server.main import Session, handle_command, user_files_dir


def _login_session(db_path, username, password="correct-password"):
    create_user(username, password, db_path)
    session = Session(ip="10.0.0.1")
    response = handle_command(
        {"command": "LOGIN", "username": username, "password": password},
        session,
        db_path,
    )
    assert response["status"] == "OK"
    return session


def _list(session, db_path):
    return handle_command({"command": "LIST"}, session, db_path)


def test_list_requires_login(tmp_path):
    response = handle_command({"command": "LIST"}, Session(), tmp_path / "users.db")
    assert response == {"status": "ERROR", "response": "Login required"}


def test_empty_list_creates_directory_and_returns_no_files(tmp_path):
    db_path = tmp_path / "users.db"
    session = _login_session(db_path, "Alice")

    response = _list(session, db_path)

    assert response == {"status": "OK", "files": []}
    assert user_files_dir(db_path, "Alice").is_dir()


def test_list_returns_regular_files_sorted_with_sizes(tmp_path):
    db_path = tmp_path / "users.db"
    session = _login_session(db_path, "Alice")
    directory = user_files_dir(db_path, "Alice", create=True)
    (directory / "b.txt").write_bytes(b"12345")
    (directory / "a.txt").write_bytes(b"")

    response = _list(session, db_path)

    assert response == {
        "status": "OK",
        "files": [
            {"name": "a.txt", "size": 0},
            {"name": "b.txt", "size": 5},
        ],
    }


def test_list_hides_partial_uploads_directories_and_symlinks(tmp_path):
    db_path = tmp_path / "users.db"
    session = _login_session(db_path, "Alice")
    directory = user_files_dir(db_path, "Alice", create=True)
    (directory / "real.txt").write_bytes(b"ok")
    (directory / "unfinished.bin.part").write_bytes(b"partial")
    (directory / "subdir").mkdir()
    (directory / "link.txt").symlink_to(tmp_path / "users.db")

    response = _list(session, db_path)

    assert response["files"] == [{"name": "real.txt", "size": 2}]


def test_users_only_see_their_own_files(tmp_path):
    db_path = tmp_path / "users.db"
    alice = _login_session(db_path, "Alice")
    bob = _login_session(db_path, "Bob")
    (user_files_dir(db_path, "Alice", create=True) / "alice.txt").write_bytes(b"a")
    (user_files_dir(db_path, "Bob", create=True) / "bob.txt").write_bytes(b"bb")

    assert _list(alice, db_path)["files"] == [{"name": "alice.txt", "size": 1}]
    assert _list(bob, db_path)["files"] == [{"name": "bob.txt", "size": 2}]


def test_list_refuses_too_many_entries(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "MAX_LIST_ENTRIES", 2)
    db_path = tmp_path / "users.db"
    session = _login_session(db_path, "Alice")
    directory = user_files_dir(db_path, "Alice", create=True)
    for name in ("a", "b", "c"):
        (directory / name).write_bytes(b"x")

    response = _list(session, db_path)

    assert response == {
        "status": "ERROR",
        "response": "Too many files to list (limit 2)",
    }


@pytest.mark.parametrize("bad_name", ["../Alice", "a/b", "", ".."])
def test_user_files_dir_rejects_invalid_names(tmp_path, bad_name):
    with pytest.raises(ValueError, match="Invalid username"):
        user_files_dir(tmp_path / "users.db", bad_name)
