import socket

from shared.protocol import receive_message, send_message

HOST = "127.0.0.1"
PORT = 5000


def main() -> None:
    with socket.create_connection((HOST, PORT), timeout=5) as client:
        print(f"Connected to server at {HOST}:{PORT}")

        request = {"command": "PING"}
        send_message(client, request)

        response = receive_message(client)
        print(f"Received response: {response}")


if __name__ == "__main__":
    main()
