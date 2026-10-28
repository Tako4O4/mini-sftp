import socket
import subprocess
import sys
import time


def test_tcp_communication():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]

    server_code = """
import socket
import sys

from server.main import HOST

port = int(sys.argv[1])

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.bind((HOST, port))
    server.listen()

    connection, _ = server.accept()

    with connection:
        connection.settimeout(3)
        data = connection.recv(1024)
        
        connection.sendall(b"Hello from server!")
"""

    server = subprocess.Popen(
        [sys.executable, "-c", server_code, str(port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    try:
        deadline = time.monotonic() + 3

        while True:
            try:
                client = socket.create_connection(
                    ("127.0.0.1", port),
                    timeout=1,
                )
                break
            except ConnectionRefusedError as exception:
                if server.poll() is not None:
                    raise RuntimeError(
                        "Server exited before accepting connections"
                    ) from exception
                if time.monotonic() >= deadline:
                    raise TimeoutError(
                        "Server did not start within 3 seconds"
                    ) from exception
                time.sleep(0.05)

        with client:
            client.settimeout(3)
            client.sendall(b"Hello from client!")

    finally:
        server.kill()
        server.communicate()  # Wait for the server process to terminate
