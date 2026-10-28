import argparse
import getpass
import hashlib
import hmac
import re
import secrets
import sqlite3
from pathlib import Path

DEFAULT_DB = Path("data/users.db")
USERNAME_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9_-]{2,31}")

SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1


def validate_password(password: str) -> None:
    size = len(password.encode("utf-8"))
    if not 8 <= size <= 1024:
        raise ValueError("Password must contain 8-1024 UTF-8 bytes")


def hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=32,
        maxmem=64 * 1024 * 1024,
    )


def initialize_database(db_path: Path = DEFAULT_DB) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(db_path) as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                salt BLOB NOT NULL,
                password_hash BLOB NOT NULL
            )
            """
        )


def create_user(username: str, password: str, db_path: Path = DEFAULT_DB) -> None:
    if not USERNAME_PATTERN.fullmatch(username):
        raise ValueError("Invalid username (pattern missmatch)")

    validate_password(password)
    initialize_database(db_path)

    salt = secrets.token_bytes(16)
    password_hash = hash_password(password, salt)

    try:
        with sqlite3.connect(db_path) as db:
            db.execute(
                """
                INSERT INTO users (username, salt, password_hash)
                VALUES (?, ?, ?)
                """,
                (username, salt, password_hash),
            )
    except sqlite3.IntegrityError as error:
        raise ValueError("Username already exists") from error


def verify_password(username: str, password: str, db_path: Path = DEFAULT_DB) -> bool:
    if not USERNAME_PATTERN.fullmatch(username):
        return False
    if len(password.encode("utf-8")) > 1024:
        return False

    initialize_database(db_path)

    with sqlite3.connect(db_path) as db:
        row = db.execute(
            """
            SELECT salt, password_hash
            FROM users
            WHERE username = ?
            """,
            (username,),
        ).fetchone()

    if row is None:
        return False

    salt, stored_hash = row
    candidate_hash = hash_password(password, salt)

    return hmac.compare_digest(candidate_hash, stored_hash)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["add-user"])
    parser.add_argument("username")
    args = parser.parse_args()

    password = getpass.getpass("Password: ")
    confirmation = getpass.getpass("Confirm Password: ")

    if password != confirmation:
        parser.error("Passwords do not match")

    try:
        create_user(args.username, password)
    except ValueError as error:
        parser.error(str(error))

    print(f"User '{args.username}' created successfully.")


if __name__ == "__main__":
    main()
