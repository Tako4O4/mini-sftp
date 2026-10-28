import socket
from threading import Thread

from server.main import handle_client
from shared.protocol import receive_message, send_message


def test_tcp_communication():
    with socket.create_server(("127.0.0.1", 0)) as server:
        server.settimeout(3)
        port = server.getsockname()[1]
        errors = []

        def serve_one_client():
            try:
                connection, _ = server.accept()
                with connection:
                    connection.settimeout(3)
                    handle_client(connection)
            except OSError as error:
                errors.append(error)

        thread = Thread(target=serve_one_client)
        thread.start()

        try:
            with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
                client.settimeout(3)
                send_message(client, {"command": "PING"})
                response = receive_message(client)

            assert response == {"status": "OK", "response": "PONG"}
        finally:
            thread.join(timeout=5)

        assert not thread.is_alive(), "Server thread did not finish"
        assert not errors, f"Server errors: {errors}"
