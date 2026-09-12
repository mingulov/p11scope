# Shared base image for the Docker rows of the Phase 4 environment matrix
# (verify-docker.sh, verify-shared-layer.sh). Ubuntu 24.04 matches this
# host's own distro/glibc (2.39), so host-built (dynamic) p11scope-discover
# and the harness binary can be bind-mounted straight in and run unmodified
# -- no cross-container build step needed here (contrast
# scripts/verify-discover-containers.sh, which targets a *different* glibc
# and musl on purpose).
# Exact linux/amd64 manifest selected by the retained ubuntu:noble-20260810
# index; the signed snapshot freezes the complete apt dependency closure.
FROM ubuntu:noble-20260810@sha256:1e0a86e57d247923571b75e0aaf48a1449cf8c543d51fb3e07a4a7d7bfa79316
ARG UBUNTU_APT_SNAPSHOT=20260810T000000Z
RUN apt-get -S "$UBUNTU_APT_SNAPSHOT" update \
    && apt-get -S "$UBUNTU_APT_SNAPSHOT" install -y --no-install-recommends softhsm2 \
    && rm -rf /var/lib/apt/lists/*
ENV SOFTHSM2_CONF=/matrix/softhsm2.conf
RUN mkdir -p /matrix/tokens \
    && printf 'directories.tokendir = /matrix/tokens\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n' \
       > /matrix/softhsm2.conf \
    && softhsm2-util --init-token --free --label matrix --so-pin 1234 --pin 1234
CMD ["sleep", "infinity"]
