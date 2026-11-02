import pytest


@pytest.fixture
def db_credentials():
    # PLACEHOLDER values for unit tests only - not real credentials.
    return {"user": "test_user", "password": "placeholder-not-a-real-password"}
