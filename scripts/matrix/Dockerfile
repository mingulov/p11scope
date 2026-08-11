# Shared base image for the Docker rows of the Phase 4 environment matrix
# (verify-docker.sh, verify-shared-layer.sh). ubuntu:24.04 matches this
# host's own distro/glibc (2.39), so host-built (dynamic) p11scope-discover
# and the harness binary can be bind-mounted straight in and run unmodified
# -- no cross-container build step needed here (contrast
# scripts/verify-discover-containers.sh, which targets a *different* glibc
# and musl on purpose).
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends softhsm2 \
    && rm -rf /var/lib/apt/lists/*
ENV SOFTHSM2_CONF=/matrix/softhsm2.conf
RUN mkdir -p /matrix/tokens \
    && printf 'directories.tokendir = /matrix/tokens\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n' \
       > /matrix/softhsm2.conf \
    && softhsm2-util --init-token --free --label matrix --so-pin 1234 --pin 1234
CMD ["sleep", "infinity"]
