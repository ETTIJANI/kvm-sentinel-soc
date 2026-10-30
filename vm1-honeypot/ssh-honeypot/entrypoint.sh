#!/usr/bin/env bash
#
# entrypoint.sh — start rsyslog, mirror auth.log to stdout, then sshd.
#
# rsyslogd is what turns sshd's syslog() calls into the traditional
# "Oct 30 10:11:12 <host> sshd[pid]: Failed password for root from ..." lines
# that promtail ships and the SOC parser understands. sshd alone (-E file)
# would give a different, harder-to-parse format.
set -Eeuo pipefail

LOG_FILE="/var/log/auth.log"
mkdir -p /run/sshd

# Host keys are generated on first start: baking them into the image would give
# every student the same fingerprint.
ssh-keygen -A >/dev/null

# Fake, intentionally weak root password (documented in the README).
echo 'root:toor' | chpasswd

# The bind mount may be empty on a fresh VM; make sure rsyslog can append.
touch "$LOG_FILE"
chmod 0644 "$LOG_FILE"

echo "[honeypot] starting rsyslog (auth -> ${LOG_FILE})"
rsyslogd

# Mirror the auth stream into the container log so that `docker compose logs -f`
# is enough to debug a demo without shelling into the VM.
tail -n0 -F "$LOG_FILE" &

echo "[honeypot] starting sshd on 0.0.0.0:2222 (LogLevel VERBOSE)"
exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config
