"""Limits failed login attempts per username and per client address.

A key is blocked while it has `limit` or more failed attempts inside the last
`window` seconds. Once the oldest of those failures ages out, the key is open
again. State is kept in memory, so it resets when the server restarts.
"""

import threading
import time
from collections import deque
from collections.abc import Callable

USER_FAILURE_LIMIT = 5  # Failed logins allowed per username...
IP_FAILURE_LIMIT = 20  # ...and per client address...
WINDOW_SECONDS = 300  # ...within this window


class FailureTracker:
    """Counts failures per key within a sliding time window. Thread-safe."""

    def __init__(
        self,
        limit: int,
        window: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.limit = limit
        self.window = window
        self._clock = clock
        self._events: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def _prune(self, now: float) -> None:
        """Drop failures older than the window, and keys with none left."""
        cutoff = now - self.window
        for key in list(self._events):
            events = self._events[key]
            while events and events[0] <= cutoff:
                events.popleft()
            if not events:
                del self._events[key]

    def is_blocked(self, key: str) -> bool:
        with self._lock:
            self._prune(self._clock())
            return len(self._events.get(key, ())) >= self.limit

    def record_failure(self, key: str) -> None:
        with self._lock:
            now = self._clock()
            self._prune(now)
            self._events.setdefault(key, deque()).append(now)

    def clear(self, key: str) -> None:
        with self._lock:
            self._events.pop(key, None)


class LoginLimiter:
    """Blocks logins by username and by client address.

    Usernames are counted whether or not the account exists, so the response
    to a blocked attempt does not reveal which accounts exist.
    """

    def __init__(
        self,
        user_limit: int = USER_FAILURE_LIMIT,
        ip_limit: int = IP_FAILURE_LIMIT,
        window: float = WINDOW_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.by_user = FailureTracker(user_limit, window, clock)
        self.by_ip = FailureTracker(ip_limit, window, clock)

    def is_blocked(self, username: str, ip: str | None) -> bool:
        if self.by_user.is_blocked(username):
            return True
        return ip is not None and self.by_ip.is_blocked(ip)

    def record_failure(self, username: str, ip: str | None) -> None:
        self.by_user.record_failure(username)
        if ip is not None:
            self.by_ip.record_failure(ip)

    def record_success(self, username: str) -> None:
        # Only the username counter resets. The address counter does not, so
        # an attacker cannot clear it by logging in to an account they own.
        self.by_user.clear(username)
