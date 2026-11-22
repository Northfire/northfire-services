#!/bin/bash
# Northfire Services: build and install.
# Built by Kyle Bargman, 2026-11-22.
#
#   northfire/install.sh [install dir]      (default: ~/northfire-services)
#
# Needs: cmake (3.20+), a C++17 compiler, libargon2-dev, libssl-dev
# (Debian/Ubuntu: apt install build-essential cmake libargon2-dev libssl-dev gettext).
# Your existing *.conf files are never overwritten: new copies are written as *.conf.new.
set -e
cd "$(dirname "$0")/.."
DEST="${1:-$HOME/northfire-services}"

for m in enc_argon2 ssl_openssl; do
	[ -e "modules/$m.cpp" ] || ln -s "extra/$m.cpp" "modules/$m.cpp"
done
cmake -B build -S . -DINSTDIR="$DEST" -DDEFUMASK=077 -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc 2>/dev/null || echo 2)"
cmake --install build

python3 northfire/make-conf.py >/dev/null
for f in northfire/conf/*.conf; do
	name=$(basename "$f")
	if [ -e "$DEST/conf/$name" ]; then
		cmp -s "$f" "$DEST/conf/$name" || cp "$f" "$DEST/conf/$name.new"
	else
		cp "$f" "$DEST/conf/$name"
	fi
done
[ -e "$DEST/conf/secrets.conf" ] || { cp northfire/conf/secrets.example.conf "$DEST/conf/secrets.conf"; chmod 600 "$DEST/conf/secrets.conf"; }
[ -e "$DEST/conf/local.conf" ] || cp northfire/conf/local.example.conf "$DEST/conf/local.conf"

echo
echo "Installed to $DEST."
echo "Next: edit $DEST/conf/secrets.conf (link password, RPC token) and local.conf (opers),"
echo "then start with: $DEST/bin/anoperc start"
ls "$DEST/conf/"*.new 2>/dev/null && echo "(*.conf.new: newer config files to compare with yours)" || true
