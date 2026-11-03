"""OWASP Top 10:2025 lookup, backed by data/owasp_top10_2025_cwe_map.yaml (official pages)."""

from __future__ import annotations

from dataclasses import dataclass
from functools import cache
from importlib import resources

import yaml


@dataclass(frozen=True)
class OwaspMap:
    by_cwe: dict[int, str]  # CWE number -> category id (A01..A10)
    names: dict[str, str]
    stated_counts: dict[str, int]
    retrieved: str

    def category(self, cwe: str) -> str | None:
        """`CWE-89` -> `A05`; unmapped -> None (never guessed)."""
        try:
            return self.by_cwe.get(int(cwe.split("-")[1]))
        except (IndexError, ValueError):
            return None


@cache
def load_owasp_map() -> OwaspMap:
    text = (resources.files("secaudit") / "data" / "owasp_top10_2025_cwe_map.yaml").read_text(
        "utf-8"
    )
    doc = yaml.safe_load(text)
    by_cwe: dict[int, str] = {}
    names: dict[str, str] = {}
    counts: dict[str, int] = {}
    for cid, cat in doc["categories"].items():
        names[cid] = cat["name"]
        counts[cid] = cat["cwe_count_stated"]
        for number in cat["cwes"]:
            if number in by_cwe:
                raise ValueError(f"CWE-{number} listed in both {by_cwe[number]} and {cid}")
            by_cwe[number] = cid
    return OwaspMap(by_cwe, names, counts, str(doc["retrieved"]))


def owasp_category(cwe_ids: tuple[str, ...], primary: str | None = None) -> str | None:
    """Category of the primary CWE if mapped, else of the first mapped CWE, else None."""
    owasp = load_owasp_map()
    for cwe in ([primary] if primary else []) + list(cwe_ids):
        if cwe and (category := owasp.category(cwe)):
            return category
    return None
