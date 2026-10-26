# LangChain + LangGraph governance-demo image (rahulnutakki/ardur-demo:lang).
#
# Build from the ardur repo root so the COPY paths line up:
#
#   cd /path/to/ardur
#   docker buildx build \
#     --platform linux/amd64,linux/arm64 \
#     -f examples/langchain-quickstart/Dockerfile \
#     -t rahulnutakki/ardur-demo:lang \
#     --push .
#
# The build copies the public Python runtime under python/vibap/, the
# shared demo helpers under examples/_shared/, and the framework demo
# entrypoint under examples/langchain-quickstart/demo.py. No model
# identifiers are baked in — the runtime expects ARDUR_PROVIDER plus
# the matching *_MODEL env vars at run time.

# Keep the tag for readable dependency updates while the immutable multi-arch
# index digest prevents a registry tag re-push from changing published builds.
# biscuit-python 0.4.0 embeds PyO3 0.24.1, whose supported ceiling is 3.13.
FROM python:3.15.0-slim-trixie@sha256:f5b92f2a669a4c347044f29367f31983280b648250ca94dea66f98c53bc87e58

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
        curl \
    && rm -rf /var/lib/apt/lists/*

# uid 1000 matches the SPIRE workload registration shipped in
# deploy/k8s/spire/. Keep this ID stable across rebuilds.
RUN groupadd -g 1000 ardur \
    && useradd -m -u 1000 -g 1000 -s /bin/bash ardur

WORKDIR /app

# Pinned versions chosen for behavioural parity with the host venv used
# during recording. spiffe 0.2.6 brings pyjwt<2.12 and grpcio>=1.62.
# AutoGen lives in a separate image (Dockerfile in autogen-quickstart/)
# because its protobuf~=5.29 pin collides with grpcio's protobuf 7.
RUN pip install --no-cache-dir \
    biscuit-python==0.4.0 \
    spiffe==0.2.6 \
    cedarpy==4.8.0 \
    cryptography \
    "pyjwt[crypto]<2.12" \
    requests \
    "pydantic>=2" \
    ollama \
    langchain \
    langchain-core \
    langchain-community \
    langchain-ollama \
    langchain-openai \
    langchain-anthropic \
    langgraph

COPY --chown=ardur:ardur python/vibap /app/ardur/vibap
COPY --chown=ardur:ardur python/pyproject.toml /app/ardur/pyproject.toml
COPY --chown=ardur:ardur examples/_shared/demo_scenes.py /app/demo_scenes.py
COPY --chown=ardur:ardur examples/_shared/verify_bundle.py /app/verify_bundle.py
COPY --chown=ardur:ardur examples/langchain-quickstart/demo.py /app/demo.py

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/ardur

# Drop privileges by default so the workload picks up the
# uid:1000/gid:1000 SPIRE entry even without `-u` on docker run.
USER ardur
CMD ["python", "-c", "print('ardur-demo:lang workload ready')"]
