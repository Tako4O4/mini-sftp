from server.auth import create_user
from server.main import Session, handle_command
from server.ratelimit import FailureTracker, LoginLimiter

BLOCKED = "Too many failed login attempts. Try again later."
WRONG = "Invalid username or password"


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


def attempt(db_path, username, password, limiter, ip="10.0.0.1"):
    """One LOGIN from a fresh connection, like a new client session."""
    return handle_command(
        {"command": "LOGIN", "username": username, "password": password},
        Session(ip=ip),
        db_path,
        limiter,
    )


def test_blocks_after_five_failures_even_with_correct_password(tmp_path):
    db_path = tmp_path / "users.db"
    create_user("Alice", "correct-password", db_path)
    limiter = LoginLimiter(clock=FakeClock())

    for _ in range(5):
        assert attempt(db_path, "Alice", "wrong", limiter)["response"] == WRONG

    assert attempt(db_path, "Alice", "correct-password", limiter) == {
        "status": "ERROR",
        "response": BLOCKED,
    }


def test_unblocks_after_window_passes(tmp_path):
    db_path = tmp_path / "users.db"
    create_user("Alice", "correct-password", db_path)
    clock = FakeClock()
    limiter = LoginLimiter(window=300, clock=clock)

    for _ in range(5):
        attempt(db_path, "Alice", "wrong", limiter)
    assert attempt(db_path, "Alice", "correct-password", limiter)["response"] == BLOCKED

    clock.now = 301
    assert attempt(db_path, "Alice", "correct-password", limiter)["status"] == "OK"


def test_successful_login_clears_username_counter(tmp_path):
    db_path = tmp_path / "users.db"
    create_user("Alice", "correct-password", db_path)
    limiter = LoginLimiter(clock=FakeClock())

    for _ in range(4):
        attempt(db_path, "Alice", "wrong", limiter)
    assert attempt(db_path, "Alice", "correct-password", limiter)["status"] == "OK"

    # Four more failures would be blocked if the earlier four had not been cleared.
    for _ in range(4):
        assert attempt(db_path, "Alice", "wrong", limiter)["response"] == WRONG


def test_unknown_usernames_are_limited_with_the_same_response(tmp_path):
    db_path = tmp_path / "users.db"
    create_user("Alice", "correct-password", db_path)
    limiter = LoginLimiter(clock=FakeClock())

    for _ in range(5):
        attempt(db_path, "nobody", "guess", limiter)

    blocked_unknown = attempt(db_path, "nobody", "guess", limiter)
    for _ in range(5):
        attempt(db_path, "Alice", "wrong", limiter)
    blocked_real = attempt(db_path, "Alice", "wrong", limiter)

    # Same status and text whether or not the account exists.
    assert blocked_unknown == blocked_real == {"status": "ERROR", "response": BLOCKED}


def test_address_limit_applies_across_usernames(tmp_path):
    db_path = tmp_path / "users.db"
    limiter = LoginLimiter(ip_limit=3, clock=FakeClock())

    for name in ("a", "b", "c"):
        assert (
            attempt(db_path, name, "guess", limiter, ip="10.0.0.1")["response"] == WRONG
        )

    # A new username from the same address is blocked by the address limit.
    assert attempt(db_path, "d", "guess", limiter, ip="10.0.0.1")["response"] == BLOCKED
    # Another address is not affected.
    assert attempt(db_path, "d", "guess", limiter, ip="10.0.0.2")["response"] == WRONG


def test_successful_login_does_not_clear_address_counter(tmp_path):
    db_path = tmp_path / "users.db"
    create_user("Mallory", "mallory-password", db_path)
    limiter = LoginLimiter(ip_limit=3, clock=FakeClock())

    attempt(db_path, "x", "guess", limiter)
    attempt(db_path, "y", "guess", limiter)
    # Attacker logs in to their own account from the same address...
    assert attempt(db_path, "Mallory", "mallory-password", limiter)["status"] == "OK"
    # ...which must not reset the address counter: this is the third failure.
    attempt(db_path, "z", "guess", limiter)

    assert attempt(db_path, "w", "guess", limiter)["response"] == BLOCKED


def test_failure_tracker_slides_its_window():
    clock = FakeClock()
    tracker = FailureTracker(limit=2, window=300, clock=clock)

    tracker.record_failure("k")  # t=0
    clock.now = 100
    tracker.record_failure("k")  # t=100
    clock.now = 200
    assert tracker.is_blocked("k")

    clock.now = 301  # the t=0 failure has expired, the t=100 one has not
    assert not tracker.is_blocked("k")


def test_expired_keys_are_removed_from_memory():
    clock = FakeClock()
    tracker = FailureTracker(limit=2, window=300, clock=clock)

    tracker.record_failure("gone")
    clock.now = 400
    tracker.is_blocked("other")  # any call prunes expired state

    assert "gone" not in tracker._events
