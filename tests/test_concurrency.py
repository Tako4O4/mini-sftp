import socket
import subprocess
from threading import Thread

from server.main import serve
from shared.protocol import receive_message, send_message
from shared.tls import create_client_context, create_server_context


def _make_certificates(directory):
    cert_file = directory / "server.crt"
    key_file = directory / "server.key"
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
    return cert_file, key_file


def _connect(port, client_context):
    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    return client_context.wrap_socket(raw, server_hostname="localhost")


def test_second_client_is_served_while_first_is_still_connected(tmp_path):
    cert_file, key_file = _make_certificates(tmp_path)
    server_context = create_server_context(cert_file, key_file)
    client_context = create_client_context(cert_file)

    server = socket.create_server(("127.0.0.1", 0))
    port = server.getsockname()[1]

    def run_server():
        try:
            serve(server, server_context)
        except OSError:
            pass  # Listening socket closed at the end of the test

    Thread(target=run_server, daemon=True).start()

    first = _connect(port, client_context)
    second = None
    try:
        # The first client stays connected (idle) for the whole test.
        send_message(first, {"command": "PING"})
        assert receive_message(first) == {"status": "OK", "response": "PONG"}

        # The second client must be served while the first is still open.
        second = _connect(port, client_context)
        send_message(second, {"command": "PING"})
        assert receive_message(second) == {"status": "OK", "response": "PONG"}

        # And the first client still works afterwards.
        send_message(first, {"command": "PING"})
        assert receive_message(first) == {"status": "OK", "response": "PONG"}
    finally:
        first.close()
        if second is not None:
            second.close()
        server.close()
