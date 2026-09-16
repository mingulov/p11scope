# Shared base image for the Docker rows of the Phase 4 environment matrix
# (verify-docker.sh, verify-shared-layer.sh). Host-built (dynamic)
# p11scope-discover and the harness binary need at most GLIBC_2.34 (measured
# with objdump -T on the host build) and Ubuntu 24.04 supplies 2.39, so they
# can be bind-mounted straight in and run unmodified. The build host is now
# Ubuntu 26.04 (glibc 2.43); the floor that matters is the binary's own
# requirement, not the host's glibc, so the bind-mount design still holds
# -- no cross-container build step needed here (contrast
# scripts/verify-discover-containers.sh, which targets a *different* glibc
# and musl on purpose).
# Exact linux/amd64 manifest selected by the retained ubuntu:noble-20260810
# index; the signed snapshot freezes the complete apt dependency closure.
FROM ubuntu:noble-20260810@sha256:1e0a86e57d247923571b75e0aaf48a1449cf8c543d51fb3e07a4a7d7bfa79316
ARG UBUNTU_APT_SNAPSHOT=20260810T000000Z
# ubuntu:noble ships no ca-certificates and no /etc/ssl at all, and -S rewrites
# the archive to HTTPS snapshot.ubuntu.com, so the snapshot is unreachable until
# a trust store exists. Bootstrap exactly that one package from the image's own
# http sources, then take every real package from the frozen snapshot.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && apt-get -S "$UBUNTU_APT_SNAPSHOT" update \
    && apt-get -S "$UBUNTU_APT_SNAPSHOT" install -y --no-install-recommends softhsm2 \
    && rm -rf /var/lib/apt/lists/*
ENV SOFTHSM2_CONF=/matrix/softhsm2.conf
RUN mkdir -p /matrix/tokens \
    && printf 'directories.tokendir = /matrix/tokens\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n' \
       > /matrix/softhsm2.conf \
    && softhsm2-util --init-token --free --label matrix --so-pin 1234 --pin 1234
CMD ["sleep", "infinity"]
