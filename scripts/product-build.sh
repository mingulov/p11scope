#!/bin/sh

p11scope_product_build() {
    if [ "$#" -lt 1 ]; then
        echo "usage: p11scope_product_build ordinary|prepared [BUILD_OPTIONS...]" >&2
        return 64
    fi

    case $1 in
        ordinary)
            shift
            scripts/cargo.sh +1.88 build --locked "$@"
            ;;
        prepared)
            shift
            if [ -z "${P11SCOPE_PREPARED_STABLE_CARGO-}" ] \
                || [ -z "${P11SCOPE_PREPARED_STABLE_RUSTC-}" ] \
                || [ -z "${P11SCOPE_PREPARED_BPF_CARGO-}" ] \
                || [ -z "${P11SCOPE_PREPARED_BPF_RUSTC-}" ]; then
                echo "product-build: complete prepared product-build context required" >&2
                return 65
            fi
            for p11scope_product_build_tool in \
                "$P11SCOPE_PREPARED_STABLE_CARGO" \
                "$P11SCOPE_PREPARED_STABLE_RUSTC" \
                "$P11SCOPE_PREPARED_BPF_CARGO" \
                "$P11SCOPE_PREPARED_BPF_RUSTC"
            do
                case $p11scope_product_build_tool in
                    /*) ;;
                    *)
                        echo "product-build: absolute executable prepared product-build tool required" >&2
                        unset p11scope_product_build_tool
                        return 66
                        ;;
                esac
                if [ ! -f "$p11scope_product_build_tool" ] \
                    || [ ! -x "$p11scope_product_build_tool" ]; then
                    echo "product-build: absolute executable prepared product-build tool required" >&2
                    unset p11scope_product_build_tool
                    return 66
                fi
            done
            unset p11scope_product_build_tool
            RUSTC="$P11SCOPE_PREPARED_STABLE_RUSTC" \
                P11SCOPE_PREPARED_BPF_CARGO="$P11SCOPE_PREPARED_BPF_CARGO" \
                P11SCOPE_PREPARED_BPF_RUSTC="$P11SCOPE_PREPARED_BPF_RUSTC" \
                "$P11SCOPE_PREPARED_STABLE_CARGO" build --locked --offline "$@"
            ;;
        *)
            echo "usage: p11scope_product_build ordinary|prepared [BUILD_OPTIONS...]" >&2
            return 64
            ;;
    esac
}
