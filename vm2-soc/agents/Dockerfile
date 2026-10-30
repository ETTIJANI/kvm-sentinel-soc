FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY *.py /app/

# Dedicated unprivileged user. uid 10002 is chowned on /opt/soc/reports by
# cloud-init, because the reports directory is a bind mount from the VM.
RUN useradd --uid 10002 --create-home --shell /usr/sbin/nologin sentinel \
 && mkdir -p /reports /app/state \
 && chown -R sentinel:sentinel /reports /app/state

USER sentinel

# main.py touches /app/state/heartbeat every loop iteration.
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD python3 -c "import pathlib,sys; sys.exit(0 if pathlib.Path('/app/state/heartbeat').exists() else 1)"

STOPSIGNAL SIGTERM

CMD ["python3", "-u", "main.py"]
