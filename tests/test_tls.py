import socket
import subprocess
from threading import Thread

from server.main import handle_client
from shared.protocol import receive_message, send_message
from shared.tls import create_client_context, create_server_context


def test_tls_ping(tmp_path):
    """Create temporary certificates"""
    cert_file = tmp_path / "server.crt"
    key_file = tmp_path / "server.key"

    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-noenc",
            "-sha256",
            "-keyout",
            str(key_file),
            "-out",
            str(cert_file),
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
        ],
        check=True,
        capture_output=True,
    )

    server_context = create_server_context(cert_file, key_file)
    client_context = create_client_context(cert_file)

    with socket.create_server(("127.0.0.1", 0)) as server:
        port = server.getsockname()[1]
        server.settimeout(5)
        errors = []

        def serve_one_client():
            try:
                connection, _ = server.accept()
                with connection:
                    connection.settimeout(5)
                    with server_context.wrap_socket(
                        connection,
                        server_side=True,
                    ) as secure_connection:
                        handle_client(secure_connection)
            except OSError as error:
                errors.append(error)

        thread = Thread(target=serve_one_client)
        thread.start()

        try:
            with socket.create_connection(("127.0.0.1", port), timeout=5) as connection:
                with client_context.wrap_socket(
                    connection, server_hostname="localhost"
                ) as client:
                    send_message(client, {"command": "PING"})
                    response = receive_message(client)
            assert response == {"status": "OK", "response": "PONG"}
        finally:
            thread.join(timeout=6)

        assert not thread.is_alive(), "Server thread did not finish"
        assert not errors, f"Server errors: {errors}"
