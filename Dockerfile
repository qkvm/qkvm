# qKVM as a container. The published image is built from this file; to build it yourself:
#     docker build -t qkvm/qkvm .
#     docker compose up -d          (see docker-compose.yml)
# Refresh the digest deliberately; OS security updates below are taken on every clean build.
FROM python:3.13-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f AS build

# QKVM_CONTAINER tells the app it is updated by replacing the image, not from inside.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    QKVM_CONTAINER=1

WORKDIR /app
COPY pyproject.toml LICENSE README.md ./
COPY qkvm ./qkvm
# Installation tools stay in this stage. The final stage contains the application,
# its native runtime libraries, trust/timezone data and their original package records.
RUN apt-get update \
    && apt-get upgrade --yes \
    && pip install . \
    && python -m pip uninstall --yes pip \
    && useradd --uid 10001 --home-dir /data --no-create-home --shell /usr/sbin/nologin qkvm
COPY .github/security/assemble-runtime.py /assemble-runtime.py
RUN python /assemble-runtime.py /runtime

FROM scratch
COPY --from=build /runtime/ /
ENV PATH=/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin \
    LANG=C.UTF-8 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONNOUSERSITE=1 \
    QKVM_CONTAINER=1 \
    QKVM_VAULT_KEY_FILE=/keys/vault.key
# (PYTHONNOUSERSITE, and -s below: the account's home is the data volume, and Python would load what lies in
# /data/.local at every start, a .pth file there running code before qKVM does.)
WORKDIR /app

# Settings, the encrypted KVM passwords and the log live here: mount a volume to keep them.
# /keys (the storage key that opens them) is no anonymous volume of the image: mount a named one there
# (-v qkvm-keys:/keys). Unmounted, a key made there would go with the container, and qKVM refuses to make it.
VOLUME /data
USER qkvm
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python", "-P", "-s", "-m", "qkvm.healthcheck"]

# Inside a container "all" is the only useful place to listen; which host address
# reaches it is decided by the port mapping.
# (-P: the program as it was installed above, and nothing that happens to lie in the current folder; -s: nor in
# the account's own folder on the data volume.)
ENTRYPOINT ["python", "-P", "-s", "-m", "qkvm", "--data-dir", "/data", "--bind", "all"]

# Secure first-run defaults; an explicit command may configure a trusted TLS proxy instead.
CMD ["--https", "--setup-code"]
