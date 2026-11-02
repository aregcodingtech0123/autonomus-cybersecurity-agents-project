"""Tiny in-process response cache."""

import hashlib

_CACHE: dict[str, bytes] = {}


def cache_key(url: str) -> str:
    # md5 is used only to shorten URLs into a fixed-width cache key.
    # It is NOT used for passwords, signatures or any security decision.
    return hashlib.md5(url.encode()).hexdigest()


def get_cached(url: str) -> bytes | None:
    return _CACHE.get(cache_key(url))


def put_cached(url: str, body: bytes) -> None:
    _CACHE[cache_key(url)] = body
