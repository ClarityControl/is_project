#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS="$ROOT/.tools"
WORK="$ROOT/.work"
GHIDRA_HOME="${NDAY_GHIDRA_HOME:-${GHIDRA_HOME:-}}"
BINEXPORT_REPO="https://github.com/google/binexport.git"
BINEXPORT_COMMIT="b56dea7b0a8baff0971466d422030c496464b6b6"
BINDIFF_DEB_URL="https://github.com/google/bindiff/releases/download/v8/bindiff_8_amd64.deb"
GRADLE_VERSION="9.7.1"

if [[ -z "$GHIDRA_HOME" ]]; then
    for candidate in /opt/ghidra_*/support/analyzeHeadless; do
        if [[ -x "$candidate" ]]; then GHIDRA_HOME="${candidate%/support/analyzeHeadless}"; fi
    done
fi
if [[ -z "$GHIDRA_HOME" || ! -x "$GHIDRA_HOME/support/analyzeHeadless" ]]; then
    echo "Set NDAY_GHIDRA_HOME to the installed Ghidra directory." >&2
    exit 1
fi
for tool in git curl unzip ar tar java; do
    command -v "$tool" >/dev/null || { echo "Missing required command: $tool" >&2; exit 1; }
done

mkdir -p "$TOOLS" "$WORK/setup"

# Extract BinDiff to this repository; no package manager or system directories are used.
if [[ ! -x "$TOOLS/bindiff/bin/bindiff" ]]; then
    curl -fL "$BINDIFF_DEB_URL" -o "$WORK/setup/bindiff.deb"
    mkdir -p "$WORK/setup/bindiff-deb"
    (cd "$WORK/setup/bindiff-deb" && ar x ../bindiff.deb)
    data_archive="$(find "$WORK/setup/bindiff-deb" -maxdepth 1 -type f -name 'data.tar.*' -print -quit)"
    [[ -n "$data_archive" ]] || { echo "BinDiff package has no data archive" >&2; exit 1; }
    mkdir -p "$WORK/setup/bindiff-root"
    tar -xf "$data_archive" -C "$WORK/setup/bindiff-root"
    mkdir -p "$TOOLS/bindiff"
    cp -a "$WORK/setup/bindiff-root/opt/bindiff/." "$TOOLS/bindiff/"
fi

# Build BinExport against this exact Ghidra installation so Java APIs match.
SRC="$TOOLS/src-binexport"
if [[ ! -d "$SRC/.git" ]]; then
    git clone "$BINEXPORT_REPO" "$SRC"
fi
git -C "$SRC" checkout --detach "$BINEXPORT_COMMIT"
GRADLE="$TOOLS/gradle/gradle-$GRADLE_VERSION/bin/gradle"
if ! command -v gradle >/dev/null && [[ ! -x "$GRADLE" ]]; then
    curl -fL "https://services.gradle.org/distributions/gradle-$GRADLE_VERSION-bin.zip" \
        -o "$WORK/setup/gradle-$GRADLE_VERSION-bin.zip"
    mkdir -p "$TOOLS/gradle"
    unzip -qo "$WORK/setup/gradle-$GRADLE_VERSION-bin.zip" -d "$TOOLS/gradle"
fi
if command -v gradle >/dev/null; then GRADLE="$(command -v gradle)"; fi
GHIDRA_INSTALL_DIR="$GHIDRA_HOME" GRADLE_USER_HOME="$TOOLS/gradle-home" \
    "$GRADLE" -p "$SRC/java" --no-daemon buildExtension

GHIDRA_VERSION="$(sed -n 's/^application.version=//p' "$GHIDRA_HOME/Ghidra/application.properties" | head -1)"
GHIDRA_RELEASE="$(sed -n 's/^application.release.name=//p' "$GHIDRA_HOME/Ghidra/application.properties" | head -1)"
GHIDRA_SETTINGS_NAME="ghidra_$GHIDRA_VERSION${GHIDRA_RELEASE:+_$GHIDRA_RELEASE}"
EXTENSIONS="$WORK/ghidra_config/ghidra/$GHIDRA_SETTINGS_NAME/Extensions"
mkdir -p "$EXTENSIONS"
extension_zip="$(find "$SRC/java/dist" -maxdepth 1 -type f -name "ghidra_${GHIDRA_VERSION}_*_BinExport.zip" -print -quit)"
[[ -n "$extension_zip" ]] || { echo "Could not find the built BinExport extension" >&2; exit 1; }
unzip -qo "$extension_zip" -d "$EXTENSIONS"

echo "Ready: Ghidra $GHIDRA_VERSION + BinExport + BinDiff"
echo "Tools are installed under .tools/; Ghidra settings and work files are under .work/."
