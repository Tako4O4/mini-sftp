import socket
import ssl
from dataclasses import dataclass
from threading import Thread

from server.auth import DEFAULT_DB, create_user, verify_password
from server.ratelimit import LoginLimiter
from server.storage import (
    describe_file,
    find_user_file,
    list_files,
    receive_upload,
    send_file_data,
    user_files_dir,
    validate_upload_request,
)
from shared.protocol import receive_message, send_message
from shared.tls import create_server_context

HOST = "127.0.0.1"
PORT = 5000
IDLE_TIMEOUT = 300  # Seconds a connection may sit idle before the server drops it

# Commands that may run before login. Every other command needs a logged-in session.
PUBLIC_COMMANDS = {"LOGIN", "PING", "REGISTER"}

# Shared by all connections, so failures from every client are counted together.
LOGIN_LIMITER = LoginLimiter()


@dataclass
class Session:
    """State for one client connection."""

    username: str | None = None
    ip: str | None = None  # Client address, used for login rate limiting


def handle_login(
    message: dict, session: Session, db_path, limiter: LoginLimiter
) -> dict:
    """Check credentials and mark the session as logged in on success."""
    username = message.get("username")
    password = message.get("password")

    if not isinstance(username, str) or not isinstance(password, str):
        return {
            "status": "ERROR",
            "response": "LOGIN requires string username and password",
        }

    if session.username is not None:
        return {
            "status": "ERROR",
            "response": f"Already logged in as {session.username}; LOGOUT first",
        }

    if limiter.is_blocked(username, session.ip):
        return {
            "status": "ERROR",
            "response": "Too many failed login attempts. Try again later.",
        }

    if not verify_password(username, password, db_path):
        limiter.record_failure(username, session.ip)
        return {"status": "ERROR", "response": "Invalid username or password"}

    limiter.record_success(username)
    session.username = username
    return {"status": "OK", "response": f"Logged in as {username}"}


def handle_register(message: dict, session: Session, db_path) -> dict:
    """Create a new account. Only allowed when not logged in."""
    username = message.get("username")
    password = message.get("password")

    if not isinstance(username, str) or not isinstance(password, str):
        return {
            "status": "ERROR",
            "response": "REGISTER requires string username and password",
        }

    if session.username is not None:
        return {
            "status": "ERROR",
            "response": "Log out before creating an account",
        }

    try:
        create_user(username, password, db_path)
    except ValueError as error:
        return {"status": "ERROR", "response": str(error)}

    return {
        "status": "OK",
        "response": f"Account '{username}' created. You can now LOGIN.",
    }


def handle_logout(session: Session) -> dict:
    """End the current login."""
    session.username = None
    return {"status": "OK", "response": "Logged out"}


def handle_list(session: Session, db_path) -> dict:
    """List the logged-in user's files."""
    directory = user_files_dir(db_path, session.username, create=True)
    return list_files(directory)


def handle_upload_header(message: dict) -> dict:
    """Check an UPLOAD header. READY tells the client to send the file data."""
    try:
        validate_upload_request(message)
    except ValueError as error:
        return {"status": "ERROR", "response": str(error)}
    return {"status": "READY", "response": "Send the file data"}


def finish_upload(connection: socket.socket, session: Session, request, db_path):
    """Receive the file data for an UPLOAD that was accepted with READY."""
    name, size, digest = validate_upload_request(request)
    directory = user_files_dir(db_path, session.username, create=True)
    return receive_upload(connection, directory, name, size, digest)


def handle_download_header(message: dict, session: Session, db_path) -> dict:
    """Check a DOWNLOAD request and describe the file. READY means data follows."""
    try:
        path = find_user_file(
            user_files_dir(db_path, session.username), message.get("name")
        )
    except FileNotFoundError:
        return {"status": "ERROR", "response": "No such file"}
    except ValueError as error:
        return {"status": "ERROR", "response": str(error)}

    size, digest = describe_file(path)
    return {
        "status": "READY",
        "response": "Sending file data",
        "size": size,
        "sha256": digest,
    }


def finish_download(
    connection: socket.socket, session: Session, request, db_path, header
):
    """Send the file data for a DOWNLOAD, then record the client's verdict."""
    name = request["name"]
    path = find_user_file(user_files_dir(db_path, session.username), name)
    send_file_data(connection, path, header["size"])

    verdict = receive_message(connection)  # Client's SHA-256 check result
    if verdict.get("status") == "OK":
        return {"status": "OK", "response": f"Downloaded '{name}'"}
    return {"status": "ERROR", "response": "Client reported a failed download"}


def handle_command(
    message: dict,
    session: Session | None = None,
    db_path=DEFAULT_DB,
    limiter: LoginLimiter | None = None,
) -> dict:
    """Process the received command and return a response."""
    if session is None:
        session = Session()
    if limiter is None:
        limiter = LOGIN_LIMITER

    command = message.get("command")
    if not isinstance(command, str):
        return {"status": "ERROR", "response": "Command must be a string"}

    if command not in PUBLIC_COMMANDS and session.username is None:
        return {"status": "ERROR", "response": "Login required"}

    if command == "LOGIN":
        return handle_login(message, session, db_path, limiter)

    if command == "REGISTER":
        return handle_register(message, session, db_path)

    if command == "LOGOUT":
        return handle_logout(session)

    if command == "LIST":
        return handle_list(session, db_path)

    if command == "UPLOAD":
        return handle_upload_header(message)

    if command == "DOWNLOAD":
        return handle_download_header(message, session, db_path)

    if command == "PING":
        return {"status": "OK", "response": "PONG"}

    return {"status": "ERROR", "response": f"Unknown command: {command}"}


def format_endpoint(address) -> str:
    """Render a client address as `ip:port`, bracketing IPv6 addresses."""
    if not address:
        return "unknown"
    host, port = address[0], address[1]
    if ":" in host:
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def source_label(address, session: Session) -> str:
    """Name a client for log lines: its address, plus its username once logged in."""
    endpoint = format_endpoint(address)
    if session.username is None:
        return endpoint
    return f"{session.username} ({endpoint})"


MAX_LOGGED_NAME = 64


def log_name(value) -> str:
    """Render an untrusted name safely for one log line.

    repr() quotes the value and escapes control characters, so a name containing
    a newline cannot forge extra log lines. The length is capped.
    """
    if not isinstance(value, str):
        return "<invalid>"
    if len(value) > MAX_LOGGED_NAME:
        return repr(value[:MAX_LOGGED_NAME]) + "..."
    return repr(value)


KNOWN_COMMANDS = {"DOWNLOAD", "LIST", "LOGIN", "LOGOUT", "PING", "REGISTER", "UPLOAD"}
DATA_COMMANDS = ("UPLOAD", "DOWNLOAD")  # Commands followed by raw file data


def command_for_log(request: dict) -> str:
    """Command name for logging: known names as-is, anything else escaped."""
    command = request.get("command")
    if isinstance(command, str) and command in KNOWN_COMMANDS:
        return command
    return log_name(command)


def command_detail(request: dict) -> str:
    """Extra log text naming the account or file a request is about, if any."""
    command = request.get("command")
    if command in ("LOGIN", "REGISTER"):
        return f" for user {log_name(request.get('username'))}"
    if command in DATA_COMMANDS:
        return f" file {log_name(request.get('name'))}"
    return ""


def handle_client(connection: socket.socket, db_path=DEFAULT_DB, address=None) -> None:
    """Handle requests on one connection until the client closes it."""
    session = Session(ip=address[0] if address else None)

    try:
        while True:
            try:
                request = receive_message(connection)
            except ConnectionError:
                return  # Client closed the connection

            command = request.get("command")
            response = handle_command(request, session, db_path)

            if command in DATA_COMMANDS and response["status"] == "READY":
                header = response
                send_message(connection, header)  # Data frames follow this reply
                if command == "UPLOAD":
                    response = finish_upload(connection, session, request, db_path)
                else:
                    response = finish_download(
                        connection, session, request, db_path, header
                    )

            # Log only the command name and outcome: requests can contain passwords.
            print(
                f"Command {command_for_log(request)} from "
                f"{source_label(address, session)}{command_detail(request)} "
                f"-> {response.get('status')}",
                flush=True,
            )
            send_message(connection, response)
    finally:
        print(f"Client {source_label(address, session)} disconnected", flush=True)


def serve_connection(
    connection: socket.socket, address, tls_context: ssl.SSLContext
) -> None:
    """Run the TLS handshake and session for one client. Runs in its own thread."""
    with connection:
        connection.settimeout(IDLE_TIMEOUT)

        try:
            with tls_context.wrap_socket(
                connection,
                server_side=True,
            ) as secure_connection:
                print(
                    f"TLS connection from {address} established: "
                    f"{secure_connection.version()}",
                    flush=True,
                )
                handle_client(secure_connection, address=address)
        except (ssl.SSLError, ConnectionError, OSError, ValueError) as error:
            print(f"Error handling client {address}: {error}", flush=True)


def serve(server: socket.socket, tls_context: ssl.SSLContext) -> None:
    """Accept clients forever, serving each one in a separate thread."""
    while True:
        connection, address = server.accept()
        print(f"Client connected from {address}", flush=True)

        Thread(
            target=serve_connection,
            args=(connection, address, tls_context),
            daemon=True,
        ).start()


def main() -> None:
    tls_context = create_server_context()

    with socket.create_server((HOST, PORT)) as server:
        print(f"Secure server listening on {HOST}:{PORT}", flush=True)
        serve(server, tls_context)


if __name__ == "__main__":
    main()
