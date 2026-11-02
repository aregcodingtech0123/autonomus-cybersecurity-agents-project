# secaudit scanner image: pip-audit
#
# Base image is pinned by digest (python:3.13-slim as resolved on 2026-11-02).
# Dependencies are installed from a hash-locked requirements.txt (generated with
# `uv pip compile --generate-hashes` from requirements.in). Pinned tool version: pip-audit 2.10.1.
#
# This image is run in "egress-only, no-source" mode: it only ever receives copies of
# requirements files and needs network access to reach the vulnerability service.
FROM python@sha256:ae14d4ce8771606477a81446e7ef429edd6762305fc50c84507c1041fa8285d1

LABEL org.secaudit.tool="pip-audit" \
      org.secaudit.tool.version="2.10.1"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOME=/tmp

COPY requirements.txt /opt/requirements.txt

RUN pip install --require-hashes --no-deps -r /opt/requirements.txt \
    && rm -rf /root/.cache /opt/requirements.txt \
    && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin scanner

USER 10001:10001
WORKDIR /tmp
