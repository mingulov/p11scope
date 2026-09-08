#!/bin/sh
set -eu

wrapper_root=$(CDPATH= cd -P "$(dirname "$0")/.." && pwd)
cd "$wrapper_root"

prepare_offline=false
for argument do
    case "$argument" in
        --) break ;;
        --offline|--frozen) prepare_offline=true ;;
    esac
done

if [ "$prepare_offline" = true ]; then
    python3 -I scripts/prepare-dependencies.py --offline
else
    python3 -I scripts/prepare-dependencies.py
fi

exec cargo "$@"
