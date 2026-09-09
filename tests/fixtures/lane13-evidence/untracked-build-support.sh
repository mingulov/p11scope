#!/bin/sh
if [ "$D2_MODE" = untracked-consumed-input ]; then
    case " $* " in
        *" build_support "*) printf '%s\n' build_support/bpf_tools.rs ;;
    esac
fi
exit 0
