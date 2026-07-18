#!/usr/bin/env bash
#
# Assemble a universal (Apple Silicon + Intel) DynoBox.app and package it as a
# .zip for GitHub Releases (no App Store, no .dmg).
#
#   misc/macos/make-app.sh [OUTPUT_DIR]   # default: dist/macos
#
# Env:
#   SKIP_BUILD=1            reuse existing per-arch release binaries
#   MACOS_SIGN_IDENTITY=…   Developer ID Application identity → hardened-runtime
#                          sign. Unset → ad-hoc sign (`-`).
#                          Ad-hoc is enough for non-App-Store distribution: it
#                          lets the binary launch, and a downloader just clears
#                          the Gatekeeper quarantine once (right-click → Open,
#                          or `xattr -dr com.apple.quarantine DynoBox.app`).
#
# Structural audits (always):
#   - lipo: universal binary must contain exactly arm64 + x86_64
#   - otool -L: every linked dylib must be on the system allow-list below
#   - codesign --verify --strict after signing
#
# Runtime smoke (CI workflow, not this script):
#   - Unpacks the shipped zip and runs Contents/MacOS/dynobox --version on the
#     native host arch only. The x86_64 slice is NOT executed under Rosetta —
#     Rosetta may be absent on Apple Silicon CI images. Arch membership is the
#     structural guarantee for the Intel half of the universal binary.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
cd "$REPO"

# Universal = both Mac architectures lipo'd into one binary.
TARGETS=(aarch64-apple-darwin x86_64-apple-darwin)
# Cargo package binary name from crates/dyno-gui.
CARGO_BIN_NAME="dynobox-gui"
# User-facing executable name inside the .app bundle.
BIN_NAME="dynobox"
APP_NAME="DynoBox"
OUT_DIR="${1:-$REPO/dist/macos}"
APP="$OUT_DIR/$APP_NAME.app"
ZIP="$OUT_DIR/$APP_NAME-macos-universal.zip"

# Workspace version → CFBundleShortVersionString.
VERSION="$(sed -n -E 's/^version = "([^"]+)".*/\1/p' "$REPO/Cargo.toml" | head -1)"
[ -n "$VERSION" ] || { echo "could not read version from Cargo.toml" >&2; exit 1; }

# 1. Build each arch. The shipped binary is dynobox-gui (dual-mode CLI+GUI),
#    renamed to `dynobox` inside the bundle for the user-facing path.
slices=()
for t in "${TARGETS[@]}"; do
    if [ "${SKIP_BUILD:-0}" != "1" ]; then
        rustup target add "$t" >/dev/null 2>&1 || true
        # Avoid discovering Homebrew's dynamic liblzma on macOS runners. A
        # bundled static copy keeps both universal slices self-contained.
        LZMA_API_STATIC=1 cargo build --release --locked --target "$t" -p dynobox-gui
    fi
    slice="$REPO/target/$t/release/$CARGO_BIN_NAME"
    [ -x "$slice" ] || { echo "missing slice: $slice (run without SKIP_BUILD?)" >&2; exit 1; }
    slices+=("$slice")
done

# 2. Bundle skeleton + one universal binary (named dynobox).
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
lipo -create "${slices[@]}" -output "$APP/Contents/MacOS/$BIN_NAME"
chmod +x "$APP/Contents/MacOS/$BIN_NAME"
printf 'APPL????' > "$APP/Contents/PkgInfo"

# 2b. Universal arch membership (structural — does not execute either slice).
ARCHS="$(lipo -archs "$APP/Contents/MacOS/$BIN_NAME")"
# Normalize whitespace for a stable compare.
ARCHS_NORM="$(printf '%s\n' "$ARCHS" | tr -s '[:space:]' ' ' | sed 's/^ //;s/ $//')"
EXPECTED_ARCHS="arm64 x86_64"
# Accept exactly the two required slices in either order. Quoted exact patterns
# avoid the mixed wildcard/quote expression that rejected `x86_64 arm64`.
case "$ARCHS_NORM" in
    "arm64 x86_64"|"x86_64 arm64") ;;
    *)
        echo "ERROR: expected universal arches '${EXPECTED_ARCHS}', got '${ARCHS_NORM}'" >&2
        exit 1
        ;;
esac
echo "Universal arches OK: ${ARCHS_NORM}"

# 3. Info.plist (substitute the version).
sed "s/__SHORT_VERSION__/$VERSION/g" "$HERE/Info.plist" > "$APP/Contents/Info.plist"

# 4. Ship the same README/LICENSE as other platform archives. Put them under
#    Contents/Resources so extraction still yields a single DynoBox.app while
#    the docs stay discoverable inside the bundle (Finder → Show Package
#    Contents → Contents/Resources).
[ -f "$REPO/README.md" ] || { echo "missing README.md at repo root" >&2; exit 1; }
[ -f "$REPO/LICENSE" ]   || { echo "missing LICENSE at repo root" >&2; exit 1; }
cp "$REPO/README.md" "$APP/Contents/Resources/README.md"
cp "$REPO/LICENSE"   "$APP/Contents/Resources/LICENSE"

# 5. otool -L allow-list audit (DynoBox-specific), per architecture.
#    DynoBox is an egui/eframe (glow) + rfd app — no libusb, no Homebrew xz.
#    Every load command must resolve to a system path. Reject Homebrew,
#    @rpath, @loader_path, @executable_path, and any other non-system dylib.
#    Allow-list prefixes (system frameworks + system libs only):
#      /System/Library/Frameworks/
#      /System/Library/PrivateFrameworks/
#      /usr/lib/
#      /Library/Apple/  (rare Apple-shipped libs)
#    Audit both arm64 and x86_64 slices of the universal binary. The identity
#    line (…/dynobox:) is skipped by only scanning dependency lines.
BIN_PATH="$APP/Contents/MacOS/$BIN_NAME"
audit_otool_arch() {
    local arch="$1"
    local otool_out dep bad
    echo "otool -arch ${arch} -L allow-list audit for ${BIN_PATH}"
    otool_out="$(otool -arch "$arch" -L "$BIN_PATH")"
    printf '%s\n' "$otool_out"
    bad=""
    while IFS= read -r dep; do
        [ -n "$dep" ] || continue
        case "$dep" in
            /System/Library/Frameworks/*) continue ;;
            /System/Library/PrivateFrameworks/*) continue ;;
            /usr/lib/*) continue ;;
            /Library/Apple/*) continue ;;
            *)
                bad="${bad}${dep}"$'\n'
                ;;
        esac
    done < <(printf '%s\n' "$otool_out" | tail -n +2 | awk '{print $1}')
    if [ -n "$bad" ]; then
        echo "ERROR: ${arch} slice links non-system / non-allow-listed dylibs:" >&2
        printf '%s' "$bad" >&2
        echo "Allowed prefixes: /System/Library/Frameworks/, /System/Library/PrivateFrameworks/, /usr/lib/, /Library/Apple/" >&2
        echo "Rejected patterns include Homebrew (/opt/homebrew, /usr/local), @rpath, @loader_path, @executable_path." >&2
        return 1
    fi
    echo "otool -arch ${arch} -L allow-list OK"
}
audit_otool_arch arm64
audit_otool_arch x86_64

# 6. Sign. Developer ID + hardened runtime when an identity is provided,
#    else ad-hoc — arm64 requires at least an ad-hoc signature to run.
#    Sign AFTER copying resources so the sealed tree includes them.
ENTITLEMENTS="$HERE/DynoBox.entitlements"
if [ -n "${MACOS_SIGN_IDENTITY:-}" ]; then
    codesign --force --timestamp --options runtime \
        --entitlements "$ENTITLEMENTS" --sign "$MACOS_SIGN_IDENTITY" "$APP"
else
    codesign --force --entitlements "$ENTITLEMENTS" --sign - "$APP"
fi
codesign --verify --strict --verbose=2 "$APP"

# 7. Package as .zip for the Release. Prefer ditto (preserves resource forks /
#    extended attrs on macOS); fall back to zip -ry. Zip root is DynoBox.app.
rm -f "$ZIP"
if command -v ditto >/dev/null 2>&1; then
    ditto -c -k --sequesterRsrc --keepParent "$APP" "$ZIP"
else
    (
        cd "$OUT_DIR"
        zip -ry "$(basename "$ZIP")" "$APP_NAME.app"
    )
fi

echo "Built $APP [$(lipo -archs "$APP/Contents/MacOS/$BIN_NAME")]"
echo "Packaged $ZIP  (version $VERSION)"
echo "Docs: $APP/Contents/Resources/{README.md,LICENSE}"
echo "Audited: universal arches + otool -L system allow-list + codesign --verify"
echo "Not executed here: x86_64 under Rosetta (structural arch check only; CI runs --version on the native host slice)."
