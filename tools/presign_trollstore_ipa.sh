#!/usr/bin/env bash
# Re-sign an unsigned Codemagic .ipa for the TrollStore test device.
#
# Why this exists. TrollStore sets get-task-allow on every app it installs, so
# its JIT option works. That is scored +35 by ios_get_task_allow, which gave
# every measurement from the test iPhone a permanent floor: the device could
# never read trusted, and no clean iOS baseline was obtainable. See DESIGN.md 37.
#
# TrollStore preserves entitlements already present in a binary instead of
# applying its defaults, so pseudo-signing with our own entitlements -- the same
# four it would have granted, minus get-task-allow -- removes the floor at the
# source. Nothing is suppressed server-side, and ios_process_traced (+50) stays
# live, which INTEGRITY_ALLOW_DEBUG would have disabled along with five others.
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
BUNDLE_ID=com.example.devicefingerprinting

[ -n "$LDID" ] && [ -x "$LDID" ] || { echo "ldid not found; pass its path as argument 3" >&2; exit 2; }
[ -f "$ENTS" ] || { echo "missing $ENTS" >&2; exit 2; }

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
unzip -q "$IN" -d "$WORK"
APP=$(find "$WORK/Payload" -maxdepth 1 -name '*.app' | head -1)
[ -n "$APP" ] || { echo "no .app inside $IN" >&2; exit 1; }
EXE="$APP/$(python3 -c "import plistlib,sys;print(plistlib.load(open(sys.argv[1],'rb'))['CFBundleExecutable'])" "$APP/Info.plist")"

# The CodeDirectory identifier is set to the bundle id because that is what a
# legitimately signed app has; leaving ldid to derive it from the file name
# would produce "Runner".
"$LDID" -S"$ENTS" -I"$BUNDLE_ID" "$EXE"

# Fail closed. Shipping a build that still carries get-task-allow would
# reintroduce the +35 silently, and the whole point is that it is gone.
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
