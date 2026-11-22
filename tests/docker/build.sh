#!/bin/bash
# Northfire Services test: copy the source (without .git) into the build volume,
# build and install to /work/run. Runs inside the nfsvc-test container. Built by Kyle Bargman
set -e
mkdir -p /work/src
tar -C /src --exclude=./.git --exclude=./build -cf - . | tar -C /work/src -xmf -
cd /work/src
for m in enc_argon2 ssl_openssl; do [ -e modules/$m.cpp ] || ln -s extra/$m.cpp modules/$m.cpp; done
cmake -B build -S . -DINSTDIR=/work/run -DDEFUMASK=077 -DCMAKE_BUILD_TYPE=Release >/tmp/cmake.log
cmake --build build -j4 >/tmp/build.log 2>&1 || { grep -E "error" -A3 /tmp/build.log | head -40; exit 1; }
grep -E "warning:" /tmp/build.log | grep -E "northfire|account\.cpp|misc\.cpp" | head || true
cmake --install build >/dev/null
/work/run/bin/anope --version
