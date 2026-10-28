import socket

from shared.protocol import receive_message, send_message
from shared.tls import create_client_context

HOST = "127.0.0.1"
PORT = 5000
SERVER_NAME = "localhost"


def main() -> None:
    tls_context = create_client_context()

    with socket.create_connection((HOST, PORT), timeout=5) as connection:
        with tls_context.wrap_socket(
            connection,
            server_hostname=SERVER_NAME,
        ) as client:
            print(f"Connected securely to server at {HOST}:{PORT}")

            request = {"command": "PING"}
            send_message(client, request)

            response = receive_message(client)
            print(f"Received response: {response}")


if __name__ == "__main__":
    main()
