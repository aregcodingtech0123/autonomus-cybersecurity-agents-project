"""Restore for the pre-2023 snapshot format. Nothing imports this module any more."""

import os


def restore_legacy_snapshot(snapshot_name: str) -> int:
    return os.system("tar xzf /srv/legacy/" + snapshot_name)
