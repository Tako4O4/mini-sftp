import sqlite3

import pytest

from server.auth import create_user, verify_password


def test_create_and_authenticate_user(tmp_path):
    db_path = tmp_path / "users.db"

    create_user("Alice", "correct-password", db_path)

    assert verify_password("Alice", "correct-password", db_path)


def test_wrong_password(tmp_path):
    db_path = tmp_path / "users.db"

    create_user("Alice", "correct-password", db_path)

    assert not verify_password("Alice", "wrong-password", db_path)


def test_unknown_user(tmp_path):
    db_path = tmp_path / "users.db"

    assert not verify_password("unknown", "some-password", db_path)


def test_duplicate_username(tmp_path):
    db_path = tmp_path / "users.db"

    create_user("Alice", "first-password", db_path)

    with pytest.raises(ValueError, match="already exists"):
        create_user("Alice", "second-password", db_path)


def test_password_is_not_stored_as_plaintext(tmp_path):
    db_path = tmp_path / "users.db"

    password = "my-secret-password"
    create_user("Alice", password, db_path)

    with sqlite3.connect(db_path) as db:
        salt, password_hash = db.execute(
            """
            SELECT salt, password_hash FROM users WHERE username = ?
            """,
            ("Alice",),
        ).fetchone()

    assert len(salt) == 16
    assert len(password_hash) == 32
    assert password.encode() != password_hash


def test_different_salts_for_same_password(tmp_path):
    db_path = tmp_path / "users.db"

    create_user("Alice", "shared-password", db_path)
    create_user("Bob", "shared-password", db_path)

    with sqlite3.connect(db_path) as db:
        records = db.execute(
            """
            SELECT salt, password_hash FROM users ORDER BY username
            """
        ).fetchall()

    assert records[0][0] != records[1][0]
    assert records[0][1] != records[1][1]


def test_invalid_username(tmp_path):
    with pytest.raises(ValueError, match="Invalid username"):
        create_user("../Alice", "correct-password", tmp_path / "users.db")


def test_short_password(tmp_path):
    with pytest.raises(ValueError, match="Password must contain"):
        create_user("Alice", "short", tmp_path / "users.db")
