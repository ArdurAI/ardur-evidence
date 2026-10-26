# AutoGen v0.4+ governance-demo image (rahulnutakki/ardur-demo:autogen).
#
# Build from the ardur repo root:
#
#   cd /path/to/ardur
#   docker buildx build \
#     --platform linux/amd64,linux/arm64 \
#     -f examples/autogen-quickstart/Dockerfile \
#     -t rahulnutakki/ardur-demo:autogen \
#     --push .
#
# spiffe-python's transitive protobuf >=6 collides with autogen-core's
# protobuf ~=5.29 pin, so this image drops the Python SPIFFE client and
# uses the official `spire-agent` CLI instead (production sidecar-fetch
# pattern). Same real Workload API, different real client.

# Keep tags for readable dependency updates while immutable multi-arch index
# digests prevent a registry tag re-push from changing published demo builds.

# Stage 1: pull the real spire-agent binary from the official image.
FROM ghcr.io/spiffe/spire-agent:1.15.5@sha256:3652c732b0f0d36f4dd78394230a1b1cd0ddcc29548a46c67a996b1a78c14481 AS spire

# biscuit-python 0.4.0 embeds PyO3 0.24.1, whose supported ceiling is 3.13.
FROM python:3.13.14-slim-trixie@sha256:9662417aace5ae7b8e2609cce472b72a8958e134ba372808abe9cc1a0c0125e6

ARG UTIL_LINUX_VERSION=2.41.5-0+deb13u1
ARG BSDUTILS_VERSION=1:2.41.5-0+deb13u1
ARG LOGIN_VERSION=1:4.16.0-2+really2.41.5-0+deb13u1

# Remove this targeted upgrade once the base includes the CVE-2026-53615 fix.
RUN apt-get update \
    && apt-get install -y --no-install-recommends --only-upgrade \
        bsdutils=${BSDUTILS_VERSION} \
        libblkid1=${UTIL_LINUX_VERSION} \
        liblastlog2-2=${UTIL_LINUX_VERSION} \
        libmount1=${UTIL_LINUX_VERSION} \
        libsmartcols1=${UTIL_LINUX_VERSION} \
        libuuid1=${UTIL_LINUX_VERSION} \
        login=${LOGIN_VERSION} \
        mount=${UTIL_LINUX_VERSION} \
        util-linux=${UTIL_LINUX_VERSION} \
    && apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -g 1000 ardur \
    && useradd -m -u 1000 -g 1000 -s /bin/bash ardur

# Bring in the official spire-agent binary.
COPY --from=spire /opt/spire/bin/spire-agent /usr/local/bin/spire-agent

WORKDIR /app

RUN pip install --no-cache-dir \
    biscuit-python==0.4.0 \
    cedarpy==4.8.0 \
    cryptography \
    pyjwt \
    requests \
    "pydantic>=2.10" \
    ollama \
    "autogen-core>=0.4" \
    "autogen-agentchat>=0.4" \
    "autogen-ext[ollama,openai,anthropic]>=0.4"

COPY --chown=ardur:ardur python/vibap /app/ardur/vibap
COPY --chown=ardur:ardur python/pyproject.toml /app/ardur/pyproject.toml
COPY --chown=ardur:ardur examples/_shared/demo_scenes.py /app/demo_scenes.py
COPY --chown=ardur:ardur examples/_shared/verify_bundle.py /app/verify_bundle.py
COPY --chown=ardur:ardur examples/autogen-quickstart/demo.py /app/demo.py

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/ardur

USER ardur
CMD ["python", "-c", "print('ardur-demo:autogen workload ready')"]
