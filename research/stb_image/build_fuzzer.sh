#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/../.." && pwd)"
vendor_dir="$script_dir/vendor/stb"
stb_ref="${STB_REF:-608de2239da15d9635920e3e77d664d9c13189cd}"

if ! command -v clang >/dev/null 2>&1; then
    echo "clang is required. Use the Docker build documented in README.md." >&2
    exit 1
fi

if [[ ! -d "$vendor_dir/.git" ]]; then
    mkdir -p "$script_dir/vendor"
    git clone --filter=blob:none https://github.com/nothings/stb.git "$vendor_dir"
fi

git -C "$vendor_dir" fetch --depth=1 origin "$stb_ref"
git -C "$vendor_dir" checkout --detach FETCH_HEAD
printf '%s\n' "Pinned stb source revision: $(git -C "$vendor_dir" rev-parse HEAD)"

mkdir -p "$script_dir/build"
clang -O1 -g -fno-omit-frame-pointer \
    -fsanitize=fuzzer,address,undefined \
    -I "$vendor_dir" \
    "$script_dir/fuzz_stb_image.c" \
    -o "$script_dir/build/fuzz_stb_image"

printf 'Built: %s\n' "$script_dir/build/fuzz_stb_image"
printf 'Project root: %s\n' "$repo_root"
