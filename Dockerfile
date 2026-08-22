# Use the latest Arch Linux image
FROM archlinux:latest

RUN pacman-key --init

# Update system and install required packages
RUN pacman -Syu --noconfirm && \
    pacman -S --noconfirm \
    python \
    go \
    uv \
    xorg-server-xvfb \
    xkeyboard-config \
    libx11 \
    libxext \
    libxtst \
    ca-certificates \
    wget \
    tar \
    nss \
    at-spi2-core \
    libcups \
    libxcomposite \
    libxdamage \
    libxrandr \
    mesa \
    libxshmfence \
    libxkbcommon \
    pango \
    alsa-lib \
    && pacman -Scc --noconfirm

# Create non-root user
RUN useradd -m -u 1000 fff_proxy && \
    mkdir -p /home/fff_proxy/proxy \
    /home/fff_proxy/chromium \
    /home/fff_proxy/server_certs \
    /home/fff_proxy/proxy/mitm_proxy \
    /home/fff_proxy/proxy/mitm_proxy/utls_bridge && \
    chown -R fff_proxy:fff_proxy /home/fff_proxy/proxy /home/fff_proxy/chromium /home/fff_proxy/server_certs

# Switch to appuser early
USER fff_proxy

WORKDIR /home/fff_proxy/proxy/mitm_proxy/utls_bridge

COPY --chown=fff_proxy:fff_proxy --chmod=770 mitm_proxy/utls_bridge/go.mod .
COPY --chown=fff_proxy:fff_proxy --chmod=770 mitm_proxy/utls_bridge/utls_bridge.go .
COPY --chown=fff_proxy:fff_proxy --chmod=770 mitm_proxy/utls_bridge/sidecar.py .

RUN go mod tidy
RUN go build -o utls-bridge .

WORKDIR /home/fff_proxy/proxy/mitm_proxy

COPY --chown=fff_proxy:fff_proxy --chmod=770 mitm_proxy/__init__.py .
COPY --chown=fff_proxy:fff_proxy --chmod=770 mitm_proxy/_common.py .
COPY --chown=fff_proxy:fff_proxy --chmod=770 mitm_proxy/_http1.py .
COPY --chown=fff_proxy:fff_proxy --chmod=770 mitm_proxy/_http2.py .
COPY --chown=fff_proxy:fff_proxy --chmod=770 mitm_proxy/_interceptor.py .
COPY --chown=fff_proxy:fff_proxy --chmod=770 mitm_proxy/_io.py .
COPY --chown=fff_proxy:fff_proxy --chmod=770 mitm_proxy/_policy.py .
COPY --chown=fff_proxy:fff_proxy --chmod=770 mitm_proxy/session.py .

WORKDIR /home/fff_proxy/proxy

COPY --chown=fff_proxy:fff_proxy --chmod=770 driverless.py .
COPY --chown=fff_proxy:fff_proxy --chmod=770 fetcher.py .
COPY --chown=fff_proxy:fff_proxy --chmod=770 patch_func.py .
COPY --chown=fff_proxy:fff_proxy --chmod=660 config.ini .
COPY --chown=fff_proxy:fff_proxy --chmod=660 requirements.txt .

# Download and install ungoogled-chromium
ADD --chown=fff_proxy:fff_proxy --chmod=770 https://github.com/ungoogled-software/ungoogled-chromium-portablelinux/releases/download/146.0.7680.177-1/ungoogled-chromium-146.0.7680.177-1-x86_64_linux.tar.xz /tmp/chromium.tar.xz
RUN mkdir -p /home/fff_proxy/chromium && \
    tar -xf /tmp/chromium.tar.xz -C /home/fff_proxy/chromium --strip-components=1 && \
    rm /tmp/chromium.tar.xz

# Create virtual environment and install dependencies with uv
RUN uv venv /home/fff_proxy/.venv && \
    source /home/fff_proxy/.venv/bin/activate && \
    uv pip install -r requirements.txt

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Expose the application port
EXPOSE 23000

# Stay as appuser for runtime
USER fff_proxy

# Set entrypoint to activate venv and run
ENTRYPOINT ["/bin/bash", "-c", "source /home/fff_proxy/.venv/bin/activate && exec python -OO driverless.py \"$@\"", "--"]
CMD ["--chrome", "/home/fff_proxy/chromium/chrome", \
     "--cert", "/home/fff_proxy/server_certs/server_cert.pem", \
     "--key", "/home/fff_proxy/server_certs/server_key.pem", \
     "--cacert", "/home/fff_proxy/server_certs/local_ca_cert.pem", \
     "--impersonate", "/home/fff_proxy/proxy/mitm_proxy/utls_bridge/utls-bridge", \
     "--host", "0.0.0.0"]
