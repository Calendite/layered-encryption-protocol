#!/bin/sh
# Builds the native half of the macOS CryptoProvider into two static libraries in $1:
#
#   liblepnative.a     the vendored C (mlkem-native, mldsa-native, Monocypher) behind the
#                      lep_ wrappers in src/, partially linked so only the functions declared in
#                      include/lep_native.h are visible; every upstream symbol stays private.
#   libLepCryptoKit.a  the CryptoKit wrappers in swift/.
#
# Gradle runs this before cinterop (:lep:buildLepNativeMacosArm64); it can also be run by hand.
# Needs only the Command Line Tools: clang, ld, ar, swiftc.
set -eu

out=${1:?usage: build.sh <output directory>}
here=$(cd "$(dirname "$0")" && pwd)
# The Mac app's minimum (macClient: LSMinimumSystemVersion 12.0).
target=arm64-apple-macos12.0
work="$out/obj"
mkdir -p "$work"

# Vendored code is built as upstream ships it. -Wno-unused-function because making its internal
# API static (MLK/MLD_CONFIG_INTERNAL_API_QUALIFIER) leaves entry points this build never calls.
cflags="-target $target -O2 -std=c99 -Wall -Wextra -Werror -Wno-unused-function -fstack-protector-strong -I$here/include"

xcrun clang $cflags -I"$here/third_party/mlkem-native/mlkem" -c "$here/src/lep_mlkem.c" -o "$work/lep_mlkem.o"
xcrun clang $cflags -I"$here/third_party/mldsa-native/mldsa" -c "$here/src/lep_mldsa.c" -o "$work/lep_mldsa.o"
xcrun clang $cflags -I"$here/third_party/monocypher" -c "$here/src/lep_ed25519.c" -o "$work/lep_ed25519.o"
xcrun clang $cflags -I"$here/third_party/monocypher" -c "$here/src/lep_monocypher.c" -o "$work/monocypher.o"
xcrun clang $cflags -I"$here/third_party/monocypher" -c "$here/third_party/monocypher/optional/monocypher-ed25519.c" -o "$work/monocypher-ed25519.o"

# One relocatable object exporting only the lep_ API, so Monocypher's crypto_* names cannot
# collide with another library's (libsodium uses the same ones) in whatever links this.
grep -o -E '^int lep_[a-z0-9_]+' "$here/include/lep_native.h" | sed 's/^int /_/' > "$work/exports.txt"
xcrun ld -r -arch arm64 -exported_symbols_list "$work/exports.txt" \
    "$work/lep_mlkem.o" "$work/lep_mldsa.o" "$work/lep_ed25519.o" \
    "$work/monocypher.o" "$work/monocypher-ed25519.o" -o "$work/lep_native.o"
rm -f "$out/liblepnative.a"
xcrun ar rcs "$out/liblepnative.a" "$work/lep_native.o"

# -runtime-compatibility-version none: below macOS 14 swiftc asks the linker for the toolchain's
# back-deployment archives (swiftCompatibility56, swiftCompatibilityPacks), which Kotlin/Native's
# link does not search. This code uses no parameter packs, and the 5.6 fixes only concern runtimes
# older than macOS 12.3; CryptoKit itself is part of the OS.
xcrun swiftc -parse-as-library -emit-library -static -O -warnings-as-errors \
    -runtime-compatibility-version none \
    -module-name LepCryptoKit -target "$target" \
    "$here/swift/LepCryptoKit.swift" -o "$out/libLepCryptoKit.a"
