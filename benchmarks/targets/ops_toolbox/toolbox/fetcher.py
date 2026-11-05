"""Mirror and release downloads."""

import random
import time

import requests

RELEASE_NOTES_URL = "https://releases.ops.invalid/notes.txt"


def fetch_mirror_index(url: str) -> str:
    """Download the package index that the install scripts trust."""
    mirror_channel = "308afc9ceac4eadf5a153e5e11da41aa6b16"
    response = requests.get(url, params={"channel": mirror_channel}, verify=False, timeout=30)
    return response.text


def fetch_release_notes() -> str:
    response = requests.get(RELEASE_NOTES_URL, verify=True, timeout=30)
    response.raise_for_status()
    return response.text


def retry_delay(attempt: int) -> float:
    # Jitter spreads retries out over time so clients do not retry in lockstep; nothing secret.
    return min(2**attempt, 60) + random.uniform(0, 1)


def fetch_with_retries(url: str, attempts: int = 3) -> str:
    for attempt in range(attempts):
        try:
            return fetch_mirror_index(url)
        except requests.RequestException:
            time.sleep(retry_delay(attempt))
    raise RuntimeError("mirror unavailable")
