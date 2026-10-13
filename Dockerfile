# QKVM as a container. The published image is built from this file; to build it yourself:
#     docker build -t qkvm/qkvm .
#     docker compose up -d          (see docker-compose.yml)
FROM python:3.13-slim

# QKVM_CONTAINER tells the app it is updated by replacing the image, not from inside.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    QKVM_CONTAINER=1

WORKDIR /app
COPY pyproject.toml LICENSE README.md ./
COPY qkvm ./qkvm
RUN pip install . \
    && useradd --uid 10001 --home-dir /data --no-create-home --shell /usr/sbin/nologin qkvm \
    && mkdir /data && chown qkvm:qkvm /data

# Settings, the encrypted KVM passwords and the log live here: mount a volume to keep them.
VOLUME /data
USER qkvm
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python", "-P", "-m", "qkvm.healthcheck"]

# Inside a container "all" is the only useful place to listen; which host address
# reaches it is decided by the port mapping.
# (-P: the program as it was installed above, and nothing that happens to lie in the current folder.)
ENTRYPOINT ["python", "-P", "-m", "qkvm", "--data-dir", "/data", "--bind", "all"]
