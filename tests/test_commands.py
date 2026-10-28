from server.main import handle_command


def test_handle_command():
    # Test the PING command
    ping_request = {"command": "PING"}
    ping_response = handle_command(ping_request)
    assert ping_response == {"status": "OK", "response": "PONG"}

    # Test an unknown command
    unknown_request = {"command": "UNKNOWN"}
    unknown_response = handle_command(unknown_request)
    assert unknown_response == {
        "status": "ERROR",
        "response": "Unknown command: UNKNOWN",
    }
