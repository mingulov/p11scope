#!/bin/sh
# Stage the observer and its discovery oracle as one root-owned sibling pair.
# Privileged captures intentionally refuse a user-writable helper.

stage_trusted_p11scope() {
    observer=$1
    helper=$2
    destination=$3
    sudo install -d -o root -g root -m 0755 "$destination"
    sudo install -o root -g root -m 0755 "$observer" "$destination/p11scope"
    sudo install -o root -g root -m 0755 "$helper" "$destination/p11scope-discover"
}

remove_trusted_p11scope() {
    destination=$1
    [ -z "$destination" ] && return
    sudo rm -f "$destination/p11scope" "$destination/p11scope-discover"
    sudo rmdir "$destination" 2>/dev/null || true
}
