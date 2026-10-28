import json
import socket
import struct

import pytest

from shared.protocol import (
    MAX_MESSAGE_SIZE,
    receive_message,
    send_message,
)


def test_message_round_trip():

    sender, receiver = socket.socketpair()

    with sender, receiver:
        original = {"command": "LIST", "path": "/documents"}
        send_message(sender, original)
        received = receive_message(receiver)

        assert received == original


def test_unicode_message():
    sender, receiver = socket.socketpair()

    with sender, receiver:
        original = {"message": "Hello, 世界"}

        send_message(sender, original)
        received = receive_message(receiver)

        assert received == original


def test_fragmented_message():
    sender, receiver = socket.socketpair()

    with sender, receiver:
        payload = json.dumps({"message": "Hello, 世界"}).encode("utf-8")
        header = struct.pack("!I", len(payload))

        sender.sendall(header[:2])
        sender.sendall(header[2:] + payload)

        assert receive_message(receiver) == {"message": "Hello, 世界"}


def test_connection_closed_mid_message():
    sender, receiver = socket.socketpair()

    with sender, receiver:
        sender.sendall(struct.pack("!I", 10) + b"abc")
        sender.close()

        with pytest.raises(ConnectionError):
            receive_message(receiver)


def test_oversized_message():
    sender, receiver = socket.socketpair()

    with sender, receiver:
        sender.sendall(struct.pack("!I", MAX_MESSAGE_SIZE + 1))

        with pytest.raises(ValueError):
            receive_message(receiver)
