#!/bin/sh
# Builds the vendored C and its lep_ wrappers with AddressSanitizer and UndefinedBehaviorSanitizer
# and runs sanitize.c over them. Run it after updating anything under lep/native/third_party.
set -eu

here=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

flags="-O1 -g -std=c99 -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer \
-Wno-unused-function -I$here/include"

xcrun clang $flags -I"$here/third_party/mlkem-native/mlkem" -c "$here/src/lep_mlkem.c" -o "$work/mlkem.o"
xcrun clang $flags -I"$here/third_party/mldsa-native/mldsa" -c "$here/src/lep_mldsa.c" -o "$work/mldsa.o"
xcrun clang $flags -I"$here/third_party/monocypher" -c "$here/src/lep_ed25519.c" -o "$work/ed25519.o"
xcrun clang $flags -I"$here/third_party/monocypher" -c "$here/src/lep_monocypher.c" -o "$work/monocypher.o"
xcrun clang $flags -I"$here/third_party/monocypher" -c "$here/third_party/monocypher/optional/monocypher-ed25519.c" -o "$work/monocypher-ed25519.o"
xcrun clang $flags "$here/test/sanitize.c" "$work"/*.o -o "$work/sanitize"
"$work/sanitize"
