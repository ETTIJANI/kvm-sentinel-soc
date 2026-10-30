# KVM-Sentinel-SOC — offline attack generator
#
# Runs inside the isolated 172.31.240.0/24 bridge and performs real SSH
# password authentication attempts against the honeypot. Paramiko keeps the
# timing and the failure modes close to a real brute force (a shell loop with
# sshpass would spawn a process per attempt and hit the VM's 1 vCPU much harder
# than a real attacker would).
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/tmp

RUN pip install --no-cache-dir paramiko==3.5.0

WORKDIR /app
COPY simulate_attack.py /app/simulate_attack.py
RUN chmod 0755 /app/simulate_attack.py

# No privileges are needed to open outbound TCP connections.
USER 65534:65534

ENTRYPOINT ["python3", "/app/simulate_attack.py"]
