# syntax=docker/dockerfile:1.7
#
# ThreatAtlasExporter container image.
#
# Build:   docker build -t threatatlas-exporter .
# Run:     docker run --rm -e TAE_URL=https://threatatlas.example.com -e TAE_TOKEN threatatlas-exporter products list
#
# Builds behind a TLS-intercepting proxy can pass the proxy's CA as a build secret:
#   docker build --secret id=ca,src=/path/to/ca.pem -t threatatlas-exporter .
# The CA is only used during the build and is not copied into the image.

ARG PYTHON_IMAGE=python:3.12-slim
ARG UV_VERSION=0.11.32

# ── build: resolve dependencies from uv.lock into a self-contained venv ────────────
FROM ${PYTHON_IMAGE} AS build
ARG UV_VERSION

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/tae \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN --mount=type=secret,id=ca,required=false \
    if [ -s /run/secrets/ca ]; then export PIP_CERT=/run/secrets/ca; fi; \
    pip install --no-cache-dir "uv==${UV_VERSION}"

WORKDIR /src
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src

RUN --mount=type=secret,id=ca,required=false \
    if [ -s /run/secrets/ca ]; then export SSL_CERT_FILE=/run/secrets/ca; fi; \
    uv sync --frozen --no-dev --no-editable

# ── runtime ────────────────────────────────────────────────────────────────────────
FROM ${PYTHON_IMAGE} AS runtime

LABEL org.opencontainers.image.title="threatatlas-exporter" \
      org.opencontainers.image.description="Pull, validate and report on OWASP ThreatAtlas threat models" \
      org.opencontainers.image.licenses="GPL-3.0-or-later"

# WeasyPrint needs Pango (text layout), HarfBuzz subsetting (font embedding) and fonts.
# Apt uses HTTPS sources, so builds behind a TLS-intercepting proxy can pass its CA as
# the same optional build secret.
RUN --mount=type=secret,id=ca,required=false \
    set -eu; \
    sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources; \
    CA_OPT=""; if [ -s /run/secrets/ca ]; then CA_OPT="-o Acquire::https::CAInfo=/run/secrets/ca"; fi; \
    apt-get $CA_OPT update; \
    apt-get $CA_OPT install -y --no-install-recommends \
        libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 fontconfig fonts-dejavu-core; \
    rm -rf /var/lib/apt/lists/*; \
    fc-cache -f

RUN groupadd --system --gid 10001 tae \
 && useradd --system --uid 10001 --gid tae --home-dir /work --shell /usr/sbin/nologin tae \
 && mkdir -p /work /out /config/tae \
 && chown tae:tae /work /out

COPY --from=build /opt/tae /opt/tae

# Config is read from /config/tae/config.toml (mount a ConfigMap there). Only /out
# and /tmp need to be writable, so the image works with readOnlyRootFilesystem.
ENV PATH=/opt/tae/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    XDG_CONFIG_HOME=/config \
    XDG_CACHE_HOME=/tmp/.cache \
    HOME=/work

USER 10001:10001
WORKDIR /work

ENTRYPOINT ["tae"]
CMD ["--help"]
