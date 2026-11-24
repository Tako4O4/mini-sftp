import pytest

from server import main as server_main
from server.ratelimit import LoginLimiter


@pytest.fixture(autouse=True)
def fresh_login_limiter(monkeypatch):
    """Give every test its own login limiter so failures never leak between tests."""
    monkeypatch.setattr(server_main, "LOGIN_LIMITER", LoginLimiter())
