# secaudit scanner image: Gitleaks
#
# Stage 1 downloads the release tarball and checks it twice, failing the build on any mismatch:
#   (a) the SHA-256 hard-coded below must equal the entry in the release's published checksums
#       file, and (b) the downloaded tarball must hash to that value.
# NOTE: only the SHA-256 is verified. The release signature/attestation is NOT verified.
# Hash source: gitleaks_8.30.1_checksums.txt (linux_x64), fetched 2026-11-02.
#
# Both base images are pinned by digest (python:3.13-slim and debian:bookworm-slim as resolved
# on 2026-11-02). The final image contains only the static gitleaks binary.
FROM python@sha256:ae14d4ce8771606477a81446e7ef429edd6762305fc50c84507c1041fa8285d1 AS fetch

ARG GITLEAKS_VERSION=8.30.1
ARG GITLEAKS_SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb

WORKDIR /dl
RUN python -c "import urllib.request as u; b='https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/'; f='gitleaks_${GITLEAKS_VERSION}_'; u.urlretrieve(b+f+'linux_x64.tar.gz','gitleaks.tar.gz'); u.urlretrieve(b+f+'checksums.txt','checksums.txt')" \
    && published="$(grep " gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz\$" checksums.txt | cut -d' ' -f1)" \
    && test "$published" = "$GITLEAKS_SHA256" \
    && echo "$GITLEAKS_SHA256  gitleaks.tar.gz" | sha256sum -c - \
    && tar -xzf gitleaks.tar.gz gitleaks

FROM debian@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3

LABEL org.secaudit.tool="gitleaks" \
      org.secaudit.tool.version="8.30.1"

COPY --from=fetch /dl/gitleaks /usr/local/bin/gitleaks
COPY gitleaks.toml /opt/gitleaks.toml

# /opt/no-ignore is an empty directory: pointing --gitleaks-ignore-path at it stops a scanned
# repository from shipping its own .gitleaksignore.
RUN mkdir /opt/no-ignore \
    && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin scanner

ENV HOME=/tmp
USER 10001:10001
WORKDIR /tmp
