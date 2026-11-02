from webshop.auth import hash_password
from webshop.cache import cache_key


def test_hash_password_is_deterministic():
    assert hash_password("secret") == hash_password("secret")
    assert len(hash_password("secret")) == 32


def test_cache_key_is_stable(db_credentials):
    assert cache_key("https://example.com/") == cache_key("https://example.com/")
    assert db_credentials["user"] == "test_user"
