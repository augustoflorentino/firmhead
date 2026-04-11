#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-$root/dist/firmhead/firmhead.h}
mkdir -p "$(dirname "$out")"

{
    cat "$root/include/firmhead/firmhead.h"
    echo
    echo "#if defined(FWH_IMPLEMENTATION) && !defined(FWH_IMPLEMENTATION_DONE)"
    echo "#define FWH_IMPLEMENTATION_DONE"
    for src in "$root"/src/*.h "$root"/src/*.c; do
        [ -f "$src" ] && grep -v '^#include "' "$src"
    done
    echo "#endif"
} > "$out"
echo "$out"
