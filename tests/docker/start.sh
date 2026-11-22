#!/bin/bash
# Northfire Services test: install the Northfire config into a fresh services
# directory, start UnrealIRCd and services, and wait for the link.
# Runs inside the nfsvc-test container (see run-tests.sh). Built by Kyle Bargman
set -e
RUN=/work/run
T=/work/test
pkill -f "$T/bin/anope" 2>/dev/null && sleep 1 || true
rm -rf /tmp/keep; [ -n "$KEEP" ] && cp -a "$T/data" /tmp/keep
rm -rf "$T" && mkdir -p "$T"
cp -a "$RUN"/. "$T"/
cp /src/northfire/conf/*.conf "$T/conf/"
rm -f "$T/conf/"*.example.conf
sed -i 's|#sendmailpath = .*|sendmailpath = "/src/tests/docker/fake-sendmail.sh"|' "$T/conf/anope.conf"
cat > "$T/conf/secrets.conf" <<'EOT'
uplink { host = "127.0.0.1"; ipv6 = no; ssl = no; port = 7000; password = "testlinkpass"; }
define { name = "rpc.token"; value = "testrpctoken"; }
EOT
cat > "$T/conf/local.conf" <<EOT
oper { name = "testoper"; type = "Services Root"; require_oper = yes; }
${EXTRA_LOCAL:-}
EOT
[ -n "$TLSONLY" ] && echo 'module { name = "nf_tlsonly"; }' >> "$T/conf/local.conf"
[ -n "$DB" ] && cp "$DB" "$T/data/anope.db"
[ -n "$KEEP" ] && cp -a /tmp/keep/. "$T/data/"

U=/work/unreal; CTL=unrealircd; CONF=unrealircd.conf
# Built by Kyle Bargman: or Northfire IRCd (run-tests.sh with NORTHFIRCD=...)
[ -n "$NORTHFIRCD" ] && { U=/work/unreal-nf; CTL=northfircd; CONF=northfircd.conf; }
mkdir -p $U/conf/tls
[ -f $U/conf/tls/server.cert.pem ] || openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=irc.test.local \
	-keyout $U/conf/tls/server.key.pem -out $U/conf/tls/server.cert.pem 2>/dev/null
cp /src/tests/docker/unrealircd.conf $U/conf/$CONF
$U/$CTL stop >/dev/null 2>&1 || true
pkill -f "$T/bin/anope" 2>/dev/null || true
$U/$CTL start >/tmp/unreal.log 2>&1 || { cat /tmp/unreal.log; exit 1; }
"$T/bin/anope" --confdir="$T/conf" --dbdir="$T/data" --logdir="$T/logs" --moduledir="$T/modules" --localedir="$T/locale" >/tmp/anope.log 2>&1 || { cat /tmp/anope.log; tail -30 "$T"/logs/*; exit 1; }
for i in $(seq 1 60); do
	grep -q "Successfully linked\|synced" "$T"/logs/services.log.* 2>/dev/null && break
	sleep 0.5
done
grep -h "Successfully linked\|synced\|ERROR\|rror" "$T"/logs/services.log.* | head -5
