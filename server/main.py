import socket

HOST = "127.0.0.1"
PORT = 5000


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((HOST, PORT))
        server.listen()

        print(f"Server listening on {HOST}:{PORT}")

        connection, address = server.accept()

        with connection:
            print(f"Client connected: {address}")

            data = connection.recv(1024)
            message = data.decode("utf-8")

            print(f"Received message: {message}")

            response = "Hello from server!"
            connection.sendall(response.encode("utf-8"))


if __name__ == "__main__":
    main()
