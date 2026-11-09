#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
if [ "$D2_MODE" = untracked-consumed-input ]; then
    case " $* " in
        *" build_support "*) printf '%s\n' build_support/bpf_tools.rs ;;
    esac
fi
exit 0
