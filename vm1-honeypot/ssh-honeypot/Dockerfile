# KVM-Sentinel-SOC — SSH honeypot container
#
# A deliberately weak OpenSSH server. Its only job is to be attacked and to
# write standard rsyslog auth lines to /var/log/auth.log, which the host binds
# to ./logs/auth.log so promtail can ship them to Loki.
#
# The point of this Dockerfile is that the log format is *boring*: it must look
# like any Ubuntu box, otherwise the detection exercise is worthless.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=UTC

# openssh-server: the bait.
# rsyslog:        writes /var/log/auth.log in traditional syslog format
#                 (Oct 30 10:11:12 host sshd[pid]: ...), exactly what the
#                 parser on vm-soc expects.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      openssh-server \
      rsyslog \
      procps \
      ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# sshd reads /etc/ssh/sshd_config.d/*.conf first, and for most keywords the
# FIRST value wins, so this file overrides the distribution defaults.
RUN cat > /etc/ssh/sshd_config.d/00-honeypot.conf <<'EOF'
# --- KVM-Sentinel-SOC honeypot -------------------------------------------
Port 2222
ListenAddress 0.0.0.0
Protocol 2

# The bait: password authentication with a fake, weak root password.
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords no
KbdInteractiveAuthentication no
UsePAM yes
MaxAuthTries 3
MaxStartups 50:30:100
LoginGraceTime 20

# Chatty logging: "Failed password for root from 1.2.3.4 port N ssh2" and
# "Invalid user X from ..." are what the SOC pipeline consumes.
LogLevel VERBOSE

# A honeypot that offers a shell is already generous; do not offer tunnels.
AllowTcpForwarding no
X11Forwarding no
PermitTunnel no
AllowAgentForwarding no
PrintMotd no
PrintLastLog yes
ClientAliveInterval 30
ClientAliveCountMax 2
Banner /etc/ssh/banner
Subsystem sftp internal-sftp
EOF

# Plausible generic banner — nothing here should reveal that this is a trap.
RUN cat > /etc/ssh/banner <<'EOF'
Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-105-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

  System information as of Tue Apr  2 09:14:07 UTC 2024

  System load:  0.08              Processes:             112
  Usage of /:   31.4% of 24.05GB  Users logged in:       0
  Memory usage: 18%               IPv4 address for eth0: 10.10.0.10
  Swap usage:   0%

Last login: Tue Apr  2 08:57:41 2024 from 10.10.0.1
EOF

# auth/authpriv -> /var/log/auth.log, traditional format (the Ubuntu default
# template, RSYSLOG_TraditionalFileFormat, already includes the timestamp,
# hostname and syslogtag prefix the parser relies on).
RUN cat > /etc/rsyslog.d/49-auth.conf <<'EOF'
auth,authpriv.*                 -/var/log/auth.log
EOF

RUN mkdir -p /run/sshd /var/log \
 && touch /var/log/auth.log \
 && chmod 0644 /var/log/auth.log

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh

EXPOSE 2222
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=4 \
  CMD bash -c '</dev/tcp/127.0.0.1/2222' || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
