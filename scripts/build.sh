#!/bin/zsh -f
# Builds and signs bufo, the one executable (and the drills' test host) (PLAN.md, Build and deploy):
# hardened runtime, no get-task-allow, and an embedded Info.plist carrying
# a version that only grows (the commit count, which `bufo update` will
# compare) and the six-character stamp people read.
#
# The signing identifier and identity come from .bufo/build.env when it
# exists (BUFO_IDENTIFIER, BUFO_CODESIGN_IDENTITY), so no install's names
# are in the repository; otherwise a generic identifier and the one Apple
# Development identity in the keychain.
set -euo pipefail
repo=${0:A:h:h}
cd $repo
[[ -r .bufo/build.env ]] && source .bufo/build.env
identifier=${BUFO_IDENTIFIER:-bufo}
out=$repo/.build/bufo-signed
mkdir -p $out

version=$(git rev-list --count HEAD)
commit=$(git rev-parse HEAD)
if [[ -n "$(git status --porcelain)" ]]; then stamp="${commit[1,5]}+"; else stamp="${commit[1,6]}"; fi
plist=$out/Info.plist
cat > $plist <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>$identifier</string>
<key>CFBundleVersion</key><string>$version</string>
<key>BufoStamp</key><string>$stamp</string>
</dict></plist>
PLIST

swift build -c release --product bufo -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker $plist
cp "$(swift build -c release --show-bin-path)/bufo" $out/bufo

identity=${BUFO_CODESIGN_IDENTITY:-}
if [[ -z $identity ]]; then
  identities=(${(f)"$(security find-identity -v -p codesigning | grep -v CSSMERR | sed -nE 's/^ *[0-9]+\) ([0-9A-F]{40}) "Apple Development:.*/\1/p')"})
  (( ${#identities} == 1 )) || { print -u2 "set BUFO_CODESIGN_IDENTITY in .bufo/build.env (found ${#identities} Apple Development identities)"; exit 1; }
  identity=${identities[1]}
fi
codesign --force --sign $identity --identifier $identifier --options runtime --timestamp=none $out/bufo
codesign --verify --strict $out/bufo
print "$out/bufo ($identifier, version $version, $stamp)"

# The drills' test host (Tests/TestHost), under its own identifier.
swift build -c release --product bufo-testhost
cp "$(swift build -c release --show-bin-path)/bufo-testhost" $out/bufo-testhost
codesign --force --sign $identity --identifier $identifier.testhost --options runtime --timestamp=none $out/bufo-testhost
print "$out/bufo-testhost ($identifier.testhost)"
