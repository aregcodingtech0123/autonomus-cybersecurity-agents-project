# secaudit scanner image: Bandit
#
# Base image is pinned by digest (python:3.13-slim as resolved on 2026-11-02).
# Dependencies are installed from a hash-locked requirements.txt (generated with
# `uv pip compile --generate-hashes` from requirements.in); pip refuses anything
# whose hash does not match. Pinned tool version: bandit 1.9.4.
FROM python@sha256:ae14d4ce8771606477a81446e7ef429edd6762305fc50c84507c1041fa8285d1

LABEL org.secaudit.tool="bandit" \
      org.secaudit.tool.version="1.9.4"

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
