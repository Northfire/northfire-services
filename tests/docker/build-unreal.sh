#!/bin/bash
# Northfire Services test: build UnrealIRCd from /work/unreal.tgz into /work/unreal.
# Built by Kyle Bargman
set -e
cd /work && rm -rf unrealsrc && mkdir unrealsrc && tar xzf unreal.tgz -C unrealsrc --strip-components=1 && cd unrealsrc
cat > config.settings <<'EOT'
BASEPATH="/work/unreal"
BINDIR="/work/unreal/bin"
DATADIR="/work/unreal/data"
CONFDIR="/work/unreal/conf"
MODULESDIR="/work/unreal/modules"
LOGDIR="/work/unreal/logs"
CACHEDIR="/work/unreal/cache"
DOCDIR="/work/unreal/doc"
TMPDIR="/work/unreal/tmp"
PRIVATELIBDIR="/work/unreal/lib"
PREFIXAQ="1"
MAXCONNECTIONS_REQUEST="auto"
NICKNAMEHISTORYLENGTH="2000"
DEFPERM="0600"
SSLDIR=""
REMOTEINC=""
CURLDIR=""
SHOWLISTMODES="1"
NOOPEROVERRIDE=""
OPEROVERRIDEVERIFY=""
GENCERTIFICATE="0"
EXTRAPARA=""
SANITIZER=""
ADVANCED=""
EOT
./Config -quick >/tmp/unreal-config.log 2>&1 || { tail -20 /tmp/unreal-config.log; exit 1; }
make -j4 >/tmp/unreal-make.log 2>&1 || { tail -30 /tmp/unreal-make.log; exit 1; }
make install >/dev/null
