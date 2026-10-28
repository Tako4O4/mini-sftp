import json
import socket
import struct

HEADER_SIZE = 4  # Size of the header in bytes (4 bytes for a 32-bit integer)
MAX_MESSAGE_SIZE = 1024 * 1024  # 1 MB


def receive_exactly(connection: socket.socket, size: int) -> bytes:
    """Receive exactly `size` bytes or raise an error."""
    data = bytearray()

    while len(data) < size:
        chunk = connection.recv(size - len(data))

        if not chunk:
            raise ConnectionError("Connection closed during message reception")

        data.extend(chunk)

    return data


def send_message(connection: socket.socket, message: dict) -> None:
    """Encode and send a length-prefixed JSON message."""
    payload = json.dumps(message).encode("utf-8")

    if len(payload) > MAX_MESSAGE_SIZE:
        raise ValueError("Message exceeds maximum allowed size")

    header = struct.pack("!I", len(payload))
    connection.sendall(header + payload)


def receive_message(connection: socket.socket) -> dict:
    """Receive and decode a length-prefixed JSON message."""
    heeader = receive_exactly(connection, HEADER_SIZE)
    (length,) = struct.unpack("!I", heeader)

    if length > MAX_MESSAGE_SIZE:
        raise ValueError("Received message exceeds maximum allowed size")

    payload = receive_exactly(connection, length)
    message = json.loads(payload.decode("utf-8"))

    if not isinstance(message, dict):
        raise ValueError("Received message is not a valid JSON object")

    return message
