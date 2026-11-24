"""Per-user file storage: listing, name checks, and receiving uploads."""

import hashlib
import os
import re
import socket
from pathlib import Path

from server.auth import USERNAME_PATTERN
from shared.protocol import MAX_CHUNK_SIZE, receive_bytes, send_bytes

FILES_DIR_NAME = "files"  # Stored next to the user database: data/files/<username>/
PARTIAL_SUFFIX = ".part"  # Unfinished uploads; hidden from LIST
MAX_LIST_ENTRIES = 1000  # Keeps a LIST response well under the 1 MB message limit
MAX_FILENAME_LENGTH = 255
MAX_UPLOAD_SIZE = 100 * 1024 * 1024  # 100 MiB per file
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")


def user_files_dir(db_path, username: str, create: bool = False) -> Path:
    """Return one user's file directory. Rejects names that are not usernames."""
    if not USERNAME_PATTERN.fullmatch(username):
        raise ValueError("Invalid username")

    directory = Path(db_path).parent / FILES_DIR_NAME / username
    if create:
        directory.mkdir(parents=True, exist_ok=True)
    return directory


def list_files(directory: Path) -> dict:
    """List regular files in a directory, sorted by name, as a response dict."""
    files = []
    for path in sorted(directory.iterdir()):
        if path.name.endswith(PARTIAL_SUFFIX) or path.is_symlink():
            continue
        if not path.is_file():
            continue
        if len(files) >= MAX_LIST_ENTRIES:
            return {
                "status": "ERROR",
                "response": f"Too many files to list (limit {MAX_LIST_ENTRIES})",
            }
        files.append({"name": path.name, "size": path.stat().st_size})

    return {"status": "OK", "files": files}


def validate_filename(name) -> None:
    """Accept only a plain file name: no paths, no hidden or partial files."""
    if not isinstance(name, str):
        raise ValueError("File name must be a string")
    if not 1 <= len(name) <= MAX_FILENAME_LENGTH:
        raise ValueError(f"File name must be 1-{MAX_FILENAME_LENGTH} characters")
    if name.startswith(".") or name.endswith(PARTIAL_SUFFIX):
        raise ValueError("Invalid file name")
    if any(char in name for char in "/\\") or any(ord(char) < 32 for char in name):
        raise ValueError("Invalid file name")


def validate_upload_request(request: dict) -> tuple[str, int, str]:
    """Check an UPLOAD header and return its (name, size, sha256)."""
    name = request.get("name")
    size = request.get("size")
    digest = request.get("sha256")

    validate_filename(name)
    if not isinstance(size, int) or isinstance(size, bool):
        raise ValueError("File size must be an integer")
    if not 0 <= size <= MAX_UPLOAD_SIZE:
        raise ValueError(f"File size must be 0-{MAX_UPLOAD_SIZE} bytes")
    if not isinstance(digest, str) or not SHA256_PATTERN.fullmatch(digest):
        raise ValueError("sha256 must be 64 lowercase hex characters")

    return name, size, digest


def receive_upload(
    connection: socket.socket,
    directory: Path,
    name: str,
    size: int,
    expected_sha256: str,
) -> dict:
    """Receive exactly `size` bytes into `<name>.part`, verify, then rename.

    A checksum mismatch discards the data and returns an error, and the
    connection stays usable. A broken or interrupted transfer removes the
    partial file and raises, which closes the connection.
    """
    final_path = directory / name
    part_path = directory / (name + PARTIAL_SUFFIX)
    digest = hashlib.sha256()
    received = 0

    try:
        with part_path.open("wb") as part:
            while received < size:
                chunk = receive_bytes(connection)
                if not chunk or received + len(chunk) > size:
                    raise ValueError("Upload data does not match the declared size")
                part.write(chunk)
                digest.update(chunk)
                received += len(chunk)
    except BaseException:
        part_path.unlink(missing_ok=True)
        raise

    if digest.hexdigest() != expected_sha256:
        part_path.unlink(missing_ok=True)
        return {"status": "ERROR", "response": "Checksum mismatch; upload discarded"}

    try:
        os.replace(part_path, final_path)
    except OSError:
        part_path.unlink(missing_ok=True)
        raise

    return {
        "status": "OK",
        "response": f"Uploaded '{name}' ({size} bytes)",
        "sha256": digest.hexdigest(),
    }


def find_user_file(directory: Path, name) -> Path:
    """Return the path of a file to download. Only plain regular files qualify."""
    validate_filename(name)
    path = directory / name
    if path.is_symlink() or not path.is_file():
        raise FileNotFoundError(name)
    return path


def describe_file(path: Path) -> tuple[int, str]:
    """Return (size, sha256) of a file, read in chunks."""
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(MAX_CHUNK_SIZE), b""):
            digest.update(chunk)
            size += len(chunk)
    return size, digest.hexdigest()


def send_file_data(connection: socket.socket, path: Path, size: int) -> None:
    """Send exactly `size` bytes of a file as data frames."""
    sent = 0
    with path.open("rb") as file:
        while sent < size:
            chunk = file.read(min(MAX_CHUNK_SIZE, size - sent))
            if not chunk:
                raise ValueError("File changed during download")
            send_bytes(connection, chunk)
            sent += len(chunk)
