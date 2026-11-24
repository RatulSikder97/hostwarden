#!/bin/sh
# Brings the deliberately compromised test host to life. Never run this
# anywhere except the disposable integration-test container.
set -eu

if [ -n "${AUTHORIZED_KEY:-}" ]; then
	mkdir -p /root/.ssh
	chmod 700 /root/.ssh
	printf '%s\n' "$AUTHORIZED_KEY" >> /root/.ssh/authorized_keys
	chmod 600 /root/.ssh/authorized_keys
fi

# Miner dropper pattern: stage in a hidden /tmp dir, launch, delete the binary.
mkdir -p /tmp/.X11-unix/.x
cp /opt/fakeminer /tmp/.X11-unix/.x/kdevtmpfsi
/tmp/.X11-unix/.x/kdevtmpfsi -o stratum+tcp://127.0.0.1:3333 --donate-level 1 &
sleep 1
rm -f /tmp/.X11-unix/.x/kdevtmpfsi

# Unauthenticated Redis on every interface.
redis-server --bind 0.0.0.0 --protected-mode no --daemonize yes --save '' --appendonly no

mkdir -p /run/sshd
touch /run/hostwarden-ready
exec /usr/sbin/sshd -D -e
