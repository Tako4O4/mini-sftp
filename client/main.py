import socket

HOST = "127.0.0.1"
PORT = 5000


def main():
    with socket.create_connection((HOST, PORT)) as client:
        print(f"Connected to server at {HOST}:{PORT}")

        message = "Hello from client!"
        client.sendall(message.encode("utf-8"))

        response = client.recv(1024)
        print(f"Received response: {response.decode('utf-8')}")


if __name__ == "__main__":
    main()
