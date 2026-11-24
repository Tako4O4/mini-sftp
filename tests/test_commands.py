from server.auth import create_user
from server.main import Session, handle_command


def test_ping_works_without_login():
    response = handle_command({"command": "PING"}, Session())
    assert response == {"status": "OK", "response": "PONG"}


def test_unknown_command_after_login(tmp_path):
    db_path = tmp_path / "users.db"
    create_user("Alice", "correct-password", db_path)
    session = Session()
    handle_command(
        {"command": "LOGIN", "username": "Alice", "password": "correct-password"},
        session,
        db_path,
    )

    response = handle_command({"command": "UNKNOWN"}, session, db_path)
    assert response == {
        "status": "ERROR",
        "response": "Unknown command: UNKNOWN",
    }


def test_unknown_command_before_login_requires_login():
    response = handle_command({"command": "UNKNOWN"}, Session())
    assert response == {"status": "ERROR", "response": "Login required"}


def test_non_string_command_is_rejected():
    response = handle_command({"command": ["PING"]}, Session())
    assert response["status"] == "ERROR"


def test_login_success_sets_session(tmp_path):
    db_path = tmp_path / "users.db"
    create_user("Alice", "correct-password", db_path)
    session = Session()

    response = handle_command(
        {"command": "LOGIN", "username": "Alice", "password": "correct-password"},
        session,
        db_path,
    )

    assert response["status"] == "OK"
    assert session.username == "Alice"


def test_login_failure_keeps_session_logged_out(tmp_path):
    db_path = tmp_path / "users.db"
    create_user("Alice", "correct-password", db_path)
    session = Session()

    response = handle_command(
        {"command": "LOGIN", "username": "Alice", "password": "wrong-password"},
        session,
        db_path,
    )

    assert response == {"status": "ERROR", "response": "Invalid username or password"}
    assert session.username is None


def test_register_creates_account_usable_for_login(tmp_path):
    db_path = tmp_path / "users.db"
    session = Session()

    response = handle_command(
        {"command": "REGISTER", "username": "Bob", "password": "bob-password"},
        session,
        db_path,
    )
    assert response["status"] == "OK"
    assert session.username is None  # registering does not log in

    response = handle_command(
        {"command": "LOGIN", "username": "Bob", "password": "bob-password"},
        session,
        db_path,
    )
    assert response["status"] == "OK"


def test_register_duplicate_username_is_rejected(tmp_path):
    db_path = tmp_path / "users.db"
    create_user("Bob", "bob-password", db_path)

    response = handle_command(
        {"command": "REGISTER", "username": "Bob", "password": "other-password"},
        Session(),
        db_path,
    )
    assert response == {"status": "ERROR", "response": "Username already exists"}


def test_register_invalid_input_is_rejected(tmp_path):
    response = handle_command(
        {"command": "REGISTER", "username": "../Bob", "password": "bob-password"},
        Session(),
        tmp_path / "users.db",
    )
    assert response["status"] == "ERROR"
    assert "Invalid username" in response["response"]


def test_register_while_logged_in_is_rejected(tmp_path):
    db_path = tmp_path / "users.db"
    create_user("Alice", "correct-password", db_path)
    session = Session(username="Alice")

    response = handle_command(
        {"command": "REGISTER", "username": "Bob", "password": "bob-password"},
        session,
        db_path,
    )
    assert response == {
        "status": "ERROR",
        "response": "Log out before creating an account",
    }


def test_login_while_logged_in_is_rejected(tmp_path):
    db_path = tmp_path / "users.db"
    create_user("Alice", "correct-password", db_path)
    session = Session(username="Alice")

    response = handle_command(
        {"command": "LOGIN", "username": "Alice", "password": "correct-password"},
        session,
        db_path,
    )
    assert response["status"] == "ERROR"
    assert "LOGOUT first" in response["response"]


def test_logout_clears_session(tmp_path):
    session = Session(username="Alice")

    response = handle_command({"command": "LOGOUT"}, session, tmp_path / "u.db")
    assert response == {"status": "OK", "response": "Logged out"}
    assert session.username is None


def test_logout_before_login_requires_login():
    response = handle_command({"command": "LOGOUT"}, Session())
    assert response == {"status": "ERROR", "response": "Login required"}


def test_login_with_non_string_fields_is_rejected(tmp_path):
    response = handle_command(
        {"command": "LOGIN", "username": ["Alice"], "password": "x"},
        Session(),
        tmp_path / "users.db",
    )
    assert response["status"] == "ERROR"
