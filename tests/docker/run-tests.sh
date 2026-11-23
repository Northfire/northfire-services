#!/bin/bash
# Northfire Services: build and run every integration test in a Debian 12 container
# with UnrealIRCd 6. Usage: tests/docker/run-tests.sh   Built by Kyle Bargman
set -e
cd "$(dirname "$0")/../.."
UNREAL_VERSION=6.2.7.1
docker build -q -t nfsvc-test tests/docker >/dev/null
docker rm -f nfsvc >/dev/null 2>&1 || true
# NORTHFIRCD=<path to a Northfire IRCd source>: test against Northfire IRCd instead of stock UnrealIRCd
EXTRA_MOUNT=""
[ -n "$NORTHFIRCD" ] && EXTRA_MOUNT="-v $(cd "$NORTHFIRCD" && pwd):/nfircd:ro"
docker run -d --name nfsvc -v "$PWD":/src:ro $EXTRA_MOUNT -e NORTHFIRCD=${NORTHFIRCD:+1} -v nfsvc-build:/work nfsvc-test sleep infinity >/dev/null
trap 'docker rm -f nfsvc >/dev/null 2>&1' EXIT
docker exec nfsvc bash -c "chown -R nfire /work"
if [ -n "$NORTHFIRCD" ]; then
	docker exec --user nfire nfsvc bash -c 'rm -rf /work/nfircdsrc && mkdir -p /work/nfircdsrc && tar -C /nfircd --exclude=.git --exclude=__pycache__ -cf - . | tar -C /work/nfircdsrc -xf - && cd /work/nfircdsrc && northfire/build.sh /work/unreal-nf >/tmp/nfircd-build.log 2>&1 || { tail -30 /tmp/nfircd-build.log; exit 1; }'
elif ! docker exec nfsvc test -x /work/unreal/unrealircd; then
	docker exec nfsvc bash -c "curl -sSfL -o /work/unreal.tgz https://www.unrealircd.org/downloads/unrealircd-$UNREAL_VERSION.tar.gz && chown nfire /work/unreal.tgz"
	docker exec --user nfire nfsvc /src/tests/docker/build-unreal.sh
fi
X="docker exec --user nfire -e NORTHFIRCD=${NORTHFIRCD:+1}"
$X nfsvc /src/tests/docker/build.sh
$X nfsvc /src/tests/docker/start.sh >/dev/null
$X nfsvc python3 /src/tests/docker/irc_test.py branding authguard rpc security twostep
$X -e KEEP=1 nfsvc /src/tests/docker/start.sh >/dev/null
$X nfsvc python3 /src/tests/docker/irc_test.py twostep-again passpolicy forum
$X -e TLSONLY=1 nfsvc /src/tests/docker/start.sh >/dev/null
$X nfsvc python3 /src/tests/docker/irc_test.py tlsonly
$X nfsvc python3 /src/tests/docker/make_old_db.py /work/old-anope.db >/dev/null
$X -e DB=/work/old-anope.db -e EXTRA_LOCAL='module { name = "db_flatfile"; database = "anope.db"; }' nfsvc /src/tests/docker/start.sh >/dev/null
$X nfsvc python3 /src/tests/docker/irc_test.py upgrade
$X -e KEEP=1 nfsvc /src/tests/docker/start.sh >/dev/null
$X nfsvc python3 /src/tests/docker/irc_test.py upgrade-again
echo "All Northfire Services tests passed."
