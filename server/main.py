import socket
import ssl

from shared.protocol import receive_message, send_message
from shared.tls import create_server_context

HOST = "127.0.0.1"
PORT = 5000


def handle_command(message: dict) -> dict:
    """Process the received command and return a response."""
    command = message.get("command")

    if command == "PING":
        return {"status": "OK", "response": "PONG"}

    return {"status": "ERROR", "response": f"Unknown command: {command}"}


def handle_client(connection: socket.socket) -> None:
    """Handle one client request."""
    request = receive_message(connection)
    print(f"Received request: {request}")

    response = handle_command(request)
    send_message(connection, response)


def main() -> None:
    tls_context = create_server_context()

    with socket.create_server((HOST, PORT)) as server:
        print(f"Secure server listening on {HOST}:{PORT}", flush=True)

        while True:
            connection, address = server.accept()
            print(f"Client connected from {address}", flush=True)

            with connection:
                connection.settimeout(3)

                try:
                    with tls_context.wrap_socket(
                        connection,
                        server_side=True,
                    ) as secure_connection:
                        print(
                            f"TLS connection established: {secure_connection.version()}"
                        )
                        handle_client(secure_connection)
                except (ssl.SSLError, ConnectionError, OSError, ValueError) as error:
                    print(f"Error handling client: {error}", flush=True)


if __name__ == "__main__":
    main()
