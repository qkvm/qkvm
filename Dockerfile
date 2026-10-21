# qKVM as a container. The published image is built from this file; to build it yourself:
#     docker build -t qkvm/qkvm .
#     docker compose up -d          (see docker-compose.yml)
# Refresh the digest deliberately; OS security updates below are taken on every clean build.
FROM python:3.13-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f

# QKVM_CONTAINER tells the app it is updated by replacing the image, not from inside.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    QKVM_CONTAINER=1

WORKDIR /app
COPY pyproject.toml LICENSE README.md ./
COPY qkvm ./qkvm
# The base may precede a Debian security update. Install available fixes, and remove pip after
# installing the app: container updates replace the image, so its bundled HTTP clients are not needed.
# Remove unused OS administration tools only in this immutable application image,
# after installation/user creation. Debian marks several as general-purpose OS essentials;
# qKVM needs none of them. Retain package metadata and Python-linked libraries.
RUN apt-get update \
    && apt-get upgrade --yes \
    && rm -rf /var/lib/apt/lists/* \
    && pip install . \
    && python -m pip uninstall --yes pip \
    && useradd --uid 10001 --home-dir /data --no-create-home --shell /usr/sbin/nologin qkvm \
    && mkdir /data && chown qkvm:qkvm /data \
    && apt-get purge --yes --allow-remove-essential \
        bsdutils login mount util-linux ncurses-bin \
        libblkid1 liblastlog2-2 libmount1 libsmartcols1 \
    && apt-get purge --yes --allow-remove-essential perl-base \
    && test -z "$(dpkg --audit)" \
    && find /usr -xdev -type f \( -perm -4000 -o -perm -2000 \) -exec chmod a-s {} +

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

# Secure first-run defaults; an explicit command may configure a trusted TLS proxy instead.
CMD ["--https", "--setup-code"]
