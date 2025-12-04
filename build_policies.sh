#!/bin/bash
set -eu -o pipefail

if ! uname -r | grep -q "cache-ext"; then
	echo "This script is intended to be run on a cache_ext kernel."
	echo "Please switch to the cache_ext kernel and try again."
	exit 1
fi

SCRIPT_PATH=$(realpath $0)
BASE_DIR=$(dirname $SCRIPT_PATH)
POLICY_PATH="$BASE_DIR/policies"

# Detect toolchain
CLANG_BIN=""
if command -v clang-18 >/dev/null 2>&1; then
	CLANG_BIN="$(command -v clang-18)"
elif command -v clang-16 >/dev/null 2>&1; then
	CLANG_BIN="$(command -v clang-16)"
elif command -v clang-15 >/dev/null 2>&1; then
	CLANG_BIN="$(command -v clang-15)"
elif command -v clang-14 >/dev/null 2>&1; then
	CLANG_BIN="$(command -v clang-14)"
elif command -v clang >/dev/null 2>&1; then
	CLANG_BIN="$(command -v clang)"
fi

if [[ -z "${CLANG_BIN}" ]]; then
	echo "clang not found. Please install clang (e.g., sudo apt-get install -y clang)."
	exit 1
fi

BPFTOOL_BIN="$(command -v bpftool || echo /usr/local/sbin/bpftool)"
if [[ ! -x "${BPFTOOL_BIN}" ]]; then
	echo "bpftool not found at ${BPFTOOL_BIN}. Install it or adjust PATH."
	exit 1
fi

# Always use repo-installed libbpf for custom symbols (embed rpath for runtime)
BPF_LDFLAGS="-L/usr/local/lib64 -Wl,-rpath,/usr/local/lib64 -lbpf"
USR_CFLAGS="-O2 -fsanitize=address -g -Wall -I/usr/local/include"

# Ensure we rebuild against current kernel's BTF: drop any stale artifacts
make -C "$POLICY_PATH" clean || true
rm -f "$POLICY_PATH/vmlinux.h"

make -C "$POLICY_PATH" -j \
	CLANG="${CLANG_BIN}" \
	BPFTOOL="${BPFTOOL_BIN}" \
	USERSPACE_LINKER_FLAGS="${BPF_LDFLAGS}" \
	USERSPACE_CFLAGS="${USR_CFLAGS}"
