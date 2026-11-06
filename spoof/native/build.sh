#!/usr/bin/env bash
# Build libspoof.so for arm64-v8a with the Android NDK.
set -euo pipefail

cd "$(dirname "$0")"

: "${ANDROID_NDK_HOME:=${ANDROID_NDK_ROOT:-}}"
if [[ -z "${ANDROID_NDK_HOME}" ]]; then
  echo "Set ANDROID_NDK_HOME (or ANDROID_NDK_ROOT) to an installed NDK." >&2
  exit 1
fi

case "$(uname -s)" in
  Linux*)  host=linux-x86_64 ;;
  Darwin*) host=darwin-x86_64 ;;
  MINGW*|MSYS*|CYGWIN*) host=windows-x86_64 ;;
  *) echo "Unsupported host: $(uname -s)" >&2; exit 1 ;;
esac

clangxx="${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/${host}/bin/aarch64-linux-android36-clang++"
if [[ ! -x "${clangxx}" ]]; then
  echo "NDK clang++ not found: ${clangxx}" >&2
  exit 1
fi

"${clangxx}" \
  -shared -fPIC -O2 -std=c++17 \
  -fno-exceptions -fno-rtti -fvisibility=hidden \
  -static-libstdc++ \
  -pthread \
  -Wl,-soname,libspoof.so \
  -Wl,--exclude-libs,ALL \
  -o ../libspoof.so \
  libspoof.cpp \
  -llog

echo "built $(cd .. && pwd)/libspoof.so"
