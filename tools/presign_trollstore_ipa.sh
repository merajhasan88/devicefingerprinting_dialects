#!/usr/bin/env bash
# Re-sign the unsigned Codemagic .ipa for the TrollStore test device.
#
# Why this exists. TrollStore sets get-task-allow on every app it installs so
# its JIT option works. That is scored +35 by ios_get_task_allow and gives the
# device a permanent floor: it can never read trusted, and no clean iOS baseline
# is obtainable. TrollStore *preserves* entitlements already present in a binary
# instead of applying its defaults, so pseudo-signing with our own set -- the
# same ones it would have granted, minus get-task-allow -- removes the floor at
# the source. Nothing is suppressed server-side, and ios_process_traced (+50)
# stays live, which INTEGRITY_ALLOW_DEBUG would have disabled along with five
# other rules.
#
# A .NET bundle carries more nested dylibs than a Flutter one, and a dylib at
# the BUNDLE ROOT is the documented cause of a sideloaded app that flashes and
# closes: signing tools walk Frameworks/ and PlugIns/ and miss anything else, so
# it loads with an invalid signature. This script signs every Mach-O it finds in
# the bundle, not just the main executable, which is the cheap way to avoid that
# whole class of failure.
#
# Requires ldid. There is no Debian package; fetch the static Linux build:
#   curl -L -o ldid https://github.com/ProcursusTeam/ldid/releases/download/\
# v2.1.5-procursus7/ldid_linux_x86_64 && chmod +x ldid
#
# Usage:
#   tools/presign_trollstore_ipa.sh <input.ipa> <output.ipa> [path-to-ldid]
set -euo pipefail

IN=${1:?usage: presign_trollstore_ipa.sh <input.ipa> <output.ipa> [ldid]}
OUT=${2:?usage: presign_trollstore_ipa.sh <input.ipa> <output.ipa> [ldid]}
LDID=${3:-$(command -v ldid || true)}
REPO=$(cd "$(dirname "$0")/.." && pwd)
ENTS="$REPO/ios/trollstore-entitlements.plist"
BUNDLE_ID=com.example.devicefingerprinting_dotnet

[ -n "$LDID" ] && [ -x "$LDID" ] || { echo "ldid not found; pass its path as argument 3" >&2; exit 2; }
[ -f "$ENTS" ] || { echo "missing $ENTS" >&2; exit 2; }
[ -f "$IN" ] || { echo "missing input .ipa: $IN" >&2; exit 2; }

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
unzip -q "$IN" -d "$WORK"
APP=$(find "$WORK/Payload" -maxdepth 1 -name '*.app' -type d | head -1)
[ -n "$APP" ] || { echo "no .app inside $IN" >&2; exit 1; }

EXE_NAME=$(python3 -c "import plistlib,sys;print(plistlib.load(open(sys.argv[1],'rb'))['CFBundleExecutable'])" "$APP/Info.plist")
EXE="$APP/$EXE_NAME"
[ -f "$EXE" ] || { echo "main executable $EXE_NAME not found in bundle" >&2; exit 1; }

# Nested Mach-O objects first, then the main executable last. Signing the outer
# binary before its dependencies would leave the bundle inconsistent.
NESTED=$(find "$APP" -type f \( -name '*.dylib' -o -name '*.so' \) | sort || true)
if [ -n "$NESTED" ]; then
  echo "  signing $(echo "$NESTED" | wc -l | tr -d ' ') nested Mach-O objects"
  while IFS= read -r lib; do
    [ -n "$lib" ] && "$LDID" -S "$lib"
  done <<< "$NESTED"
fi

# The CodeDirectory identifier is set to the bundle id because that is what a
# legitimately signed app carries -- and because the code_signing probe now
# reports that field, which the server compares against app_identity.bundle_id.
# Leaving ldid to derive it from the file name would report the executable's
# name instead and raise ios_signing_identifier_bundle_mismatch.
"$LDID" -S"$ENTS" -I"$BUNDLE_ID" "$EXE"

# Fail closed. Shipping a build that still carries get-task-allow would
# reintroduce the +35 silently, and removing it is the entire point.
"$LDID" -e "$EXE" > "$WORK/actual.xml"
python3 - "$WORK/actual.xml" "$ENTS" <<'PY'
import plistlib, sys
actual = plistlib.load(open(sys.argv[1], 'rb'))
want = plistlib.load(open(sys.argv[2], 'rb'))
if 'get-task-allow' in actual:
    sys.exit("FAIL: get-task-allow is still present after signing")
if actual != want:
    sys.exit("FAIL: entitlements differ from %s\n  got:  %r\n  want: %r"
             % (sys.argv[2], actual, want))
print("  entitlements verified: %d keys, no get-task-allow" % len(actual))
PY

( cd "$WORK" && zip -qry "$OUT.tmp" Payload )
mv "$OUT.tmp" "$OUT"
echo "  wrote $OUT"
echo "  sha256 $(sha256sum "$OUT" | cut -d' ' -f1)"
echo
echo "NOTE: the sha256 above is NOT what INTEGRITY_IOS_EXECUTABLE_SHA256 should"
echo "      be pinned to. TrollStore rewrites the binary during installation, so"
echo "      the baseline must be the value the device itself reports."
