# nosemgrep: dockerfile-source-not-pinned — pinning to hash breaks cross-arch builds
FROM public.ecr.aws/docker/library/python:3.13-slim

RUN pip install --no-cache-dir boto3==1.39.11 botocore==1.39.11

# Non-root user (CKV_DOCKER_3). Port 443 binding enabled via
# net.ipv4.ip_unprivileged_port_start=0 sysctl on the ECS task.
RUN useradd --create-home --shell /bin/false proxyuser
USER proxyuser

WORKDIR /app
COPY --chown=proxyuser:proxyuser egress/ ./egress/
# Minimal control_plane subset: only quarantine.py (DenialReason enum).
# The full allocation/ directory is NOT copied — its __init__.py imports
# ledger.py which pulls in providers/ and state/ (not in this image).
COPY --chown=proxyuser:proxyuser control_plane/__init__.py ./control_plane/
RUN mkdir -p control_plane/allocation && touch control_plane/allocation/__init__.py
COPY --chown=proxyuser:proxyuser control_plane/allocation/quarantine.py ./control_plane/allocation/quarantine.py

EXPOSE 443

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD ["python", "-c", "import socket; s=socket.socket(); s.settimeout(2); s.connect(('127.0.0.1',443)); s.close()"]

CMD ["python", "egress/server.py"]
