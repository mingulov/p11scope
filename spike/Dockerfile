# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends softhsm2 \
    && rm -rf /var/lib/apt/lists/*
ENV SOFTHSM2_CONF=/spike/softhsm2.conf
RUN mkdir -p /spike/tokens \
    && printf 'directories.tokendir = /spike/tokens\nobjectstore.backend = file\n' \
       > /spike/softhsm2.conf \
    && softhsm2-util --init-token --free --label spike --pin 1234 --so-pin 12345678
COPY work/discover work/harness /spike/
CMD ["sleep", "infinity"]
