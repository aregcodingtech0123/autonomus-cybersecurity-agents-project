# Pre-scan label review of the Phase 2C-A benchmark

Scope: `benchmarks/expected_findings_expansion.yaml` and the targets `shop_api`, `admin_portal` and
`ops_toolbox`. Review date: 2026-11-05. All sources below were checked on that date.

**All changes on this page happened before any scan.** No scanner has run on these three targets.

## How the first registration relates to this one

- The first registration is the tag `bench-v2-preregistered` (tag object
  `12b451bde64c26503757fa6adb7a23ea8c95ab52`, on commit `9ed9276a8b7d2f10205b108c1a35ba9c62b974b8`).
- That tag, its branch and a merge into `main` (`a24206f`) were already on `origin` when this review began.
  The tag is therefore kept unchanged, so the first set of labels stays comparable.
- The corrected labels are registered by the new tag `bench-v2.1-preregistered`.
- To see every change: `git diff bench-v2-preregistered bench-v2.1-preregistered`.

## Evidence that no scan happened

- CI ran on the first registration (runs 42001185343, 42001218041, 42001236717). In their logs, the new
  target names appear only in the benchmark checker and catalogue tests.
- Docker-marked tests, which do run scanners, scan `vuln_python_app` or a copy of it.
- Local `.secaudit/logs` from 2026-11-05 do not mention the new targets, and `audits/` holds one audit from
  2026-11-02, before the targets existed.

## Changes

| Case | Before | After | Evidence or source | Date |
|---|---|---|---|---|
| P39 | `positive` with a `match` | `unscored`, with `unscored_reason` and `pipeline_expectation`; no `match` | An unpinned range is a risk, not a demonstrated vulnerability; [`pip_audit.py`](../src/secaudit/core/scanners/pip_audit.py) records it as `unresolved` | 2026-11-05 |
| N23 | `negative`, floor 3.13.4 from memory | `unscored` | CVE-2026-107784 is a `data` filter bypass on Windows, fixed in no 3.13 release ([issue](https://github.com/python/cpython/issues/161323), [backport PR](https://github.com/python/cpython/pull/161357)); `requires-python` cannot exclude Windows | 2026-11-05 |
| P35 | Rationale assumed a version | Label unchanged; rationale and notes state `>=3.13.18,<3.14` | [PEP 706](https://peps.python.org/pep-0706/), [tarfile docs](https://docs.python.org/3.14/library/tarfile.html), [`Lib/tarfile.py` v3.13.18](https://github.com/python/cpython/blob/v3.13.18/Lib/tarfile.py) | 2026-11-05 |
| `ops_toolbox` target | `requires-python >=3.13.4,<3.14` | `>=3.13.18,<3.14`; README section added at the end | Table below | 2026-11-05 |
| P32 | 3 advisories; title and rationale said "reachable" | All 11 GHSA ids per pin; both lines kept; `reachability: not verified` | [OSV](https://api.osv.dev/v1/query): each pin has advisories; [Flask 2.2.5 metadata](https://pypi.org/pypi/Flask/2.2.5/json) accepts Werkzeug 2.2.2 | 2026-11-05 |
| P18 | Title said "reachable"; compatibility unproven | Pin unchanged; compatibility recorded; `reachability: not verified` | [FastAPI 0.115.0 metadata](https://pypi.org/pypi/fastapi/0.115.0/json), [Starlette 0.38.6 metadata](https://pypi.org/pypi/starlette/0.38.6/json): `python-multipart>=0.0.7` only under extras the manifest does not request; [FastAPI gate](https://github.com/fastapi/fastapi/blob/0.115.0/fastapi/dependencies/utils.py) | 2026-11-05 |
| P18, P19, P32 | No scoring statement | `scoring_note` added | Review decision | 2026-11-05 |
| P19 | Notes said "not reachable" for the pin | `reachability: not reachable`, scoped to GHSA-ffqj-6fqr-9h24 | [OSV](https://api.osv.dev/v1/query) lists other advisories for the pin, not assessed | 2026-11-05 |
| P38, P39 | No reachability | `reachability: not verified` | Nothing was run | 2026-11-05 |
| P16 | No field | `expected_miss_reason: no_rule` | Review decision | 2026-11-05 |
| P20, P21, P22, P23, P24 | No field | `expected_miss_reason: tool_blind` | Review decision | 2026-11-05 |
| P38 | No field | `expected_miss_reason: pipeline_gap` | The adapter reads `*requirements*.txt` only ([`pip_audit.py`](../src/secaudit/core/scanners/pip_audit.py)) | 2026-11-05 |
| P31, P34, P36, P38, P40 | Assumptions implicit | Label and confidence unchanged; `Exploitability assumptions:` sentence added | Review decision | 2026-11-05 |
| N22 | "worst case is an exception" | "no code execution; DoS risk bounded by the cap"; a crash of this one process is stated as possible | [`ast.literal_eval` docs](https://docs.python.org/3.13/library/ast.html#ast.literal_eval) warn that a small input can crash the process | 2026-11-05 |
| N26 | Query had no bound value; rationale named no lines | `report.py` lines 29, 31 and 37 add `min_total`, bound with `?`; anchor updated; rationale cites lines 26, 30, 31 | The review asked for cited bound values, and the code had none. Line numbers did not move | 2026-11-05 |
| N17 | General argument | Cites `reports.py` lines 53 and 61, `audit.html` line 4 | Target source | 2026-11-05 |
| N18 | General argument | Cites `uploads.py` lines 32 and 33 (and 34, 35) | Target source | 2026-11-05 |

Scored totals in the expansion move from 29 positives and 21 negatives to 28 and 20, plus 2 unscored.
Every quota still holds.

## tarfile fixes on the 3.13 line

Fix versions are the first `v3.13.x` tag that contains the 3.13 fix commit named in the advisory. Advisories
are from the [PSF advisory database](https://github.com/psf/advisory-database/tree/main/advisories/python).

| Advisory | CVE | Reaches `extractall(dest, filter="data")` | First 3.13 tag |
|---|---|---|---|
| PSF-2025-5 | CVE-2024-12718 | yes | 3.13.4 |
| PSF-2025-6 | CVE-2025-4138 | yes | 3.13.4 |
| PSF-2025-7 | CVE-2025-4330 | yes | 3.13.4 |
| PSF-2025-8 | CVE-2025-4435 | yes | 3.13.4 |
| PSF-2025-9 | CVE-2025-4517 | yes | 3.13.4 |
| PSF-2026-10 | CVE-2025-13462 | no, parsing differential | 3.13.13 |
| PSF-2026-26 | CVE-2026-7774 | yes | 3.13.14 |
| PSF-2026-30 | CVE-2026-11940 | yes | 3.13.15 |
| PSF-2026-32 | CVE-2026-4360 | no, `extract()` only | 3.13.15 |
| PSF-2026-38 | CVE-2026-19672 | yes, empty directories only, POSIX | 3.13.16 |
| PSF-2026-41 | CVE-2026-82049 | yes | 3.13.16 |
| PSF-2026-40 | CVE-2026-87910 | yes, platforms without links | 3.13.16 |
| PSF-2026-45 | CVE-2026-114583 | no, `tar` filter only | 3.13.18 |
| none yet (gh-161323) | CVE-2026-107784 | yes, Windows | **none** |

- 3.14 made `data` the default extraction filter. On v3.13.18, no filter still means `fully_trusted`.
- 3.13.18 was the newest 3.13 tag on the check date.
- OSV had no record for CVE-2026-107784 on the check date. The only sources are the CPython issue and PRs.
- gh-160297 is not listed: it was fixed only on 3.14 and later, and the issue says the `data` filter rejects
  that archive.

To restore N23 as a negative: wait for a 3.13 release that contains the backport, record it in
`interpreter_evidence`, raise `required_range` and `requires-python` to it, and register a new tag.
`benchmarks/check_ground_truth.py` asks for this once the entry has a fixed version.

## Pins with no advisory

OSV returned no advisory for Jinja2 3.1.6, lxml 6.1.0, psycopg2-binary 2.9.9, fastapi 0.115.0, uvicorn 0.30.6,
SQLAlchemy 2.0.35, pydantic 2.9.2, requests 2.33.1 and click 8.1.8. They need no case.

## Masking probes

Probes M01-M07 were checked against the current masker (`secaudit.core.normalize.masking.mask_text`), which is
not a scanner. Each probe's value, or both fragments for M03, passes through unchanged.

M07 was adjusted for that reason during Phase 2C-A, in commit `28914e8`. Written as one run,
`tracking_seed=<value>` was redacted by the entropy fallback, so the probe tested nothing. It now has spaces
around `=`.
