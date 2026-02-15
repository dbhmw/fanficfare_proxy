# Use the latest Arch Linux image
FROM archlinux:latest

RUN pacman-key --init

# Update system and install required packages
RUN pacman -Syu --noconfirm && \
    pacman -S --noconfirm \
    python \
    uv \
    xorg-server-xvfb \
    xorg-setxkbmap \
    xorg-xrandr \
    xkeyboard-config \
    xorg-xinit \
    libx11 \
    libxext \
    libxrender \
    libxtst \
    ca-certificates \
    wget \
    tar \
    nss \
    nspr \
    at-spi2-core \
    libcups \
    libxcomposite \
    libxdamage \
    libxrandr \
    mesa \
    alsa-lib \
    libxshmfence \
    libxkbcommon \
    cairo \
    pango \
    && pacman -Scc --noconfirm

# Create non-root user
RUN useradd -m -u 1000 fff_proxy && \
    mkdir -p /home/fff_proxy/proxy /home/fff_proxy/chromium /home/fff_proxy/certs && \
    chown -R fff_proxy:fff_proxy /home/fff_proxy/proxy /home/fff_proxy/chromium /home/fff_proxy/certs

# Switch to appuser early
USER fff_proxy

# Set working directory
WORKDIR /home/fff_proxy/proxy

# Copy your project files
COPY --chown=fff_proxy:fff_proxy --chmod=770 driverless.py .
COPY --chown=fff_proxy:fff_proxy --chmod=770 patch_func.py .
COPY --chown=fff_proxy:fff_proxy --chmod=770 proxy_server.py .
COPY --chown=fff_proxy:fff_proxy --chmod=770 config.ini .
COPY --chown=fff_proxy:fff_proxy --chmod=770 requirements.txt .

# Download and install ungoogled-chromium
ADD --chown=fff_proxy:fff_proxy --chmod=770 https://github.com/ungoogled-software/ungoogled-chromium-portablelinux/releases/download/145.0.7632.45-1/ungoogled-chromium-145.0.7632.45-1-x86_64_linux.tar.xz /tmp/chromium.tar.xz
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

# Set entrypoint to activate venv and run main.py
ENTRYPOINT ["/bin/bash", "-c", "source /home/fff_proxy/.venv/bin/activate && exec python driverless.py \"$@\"", "--"]
CMD ["--chrome", "/home/fff_proxy/chromium/chrome", \
     "--cert", "/home/fff_proxy/certs/server_crt.pem", \
     "--key", "/home/fff_proxy/certs/server_key.pem", \
     "--cacert", "/home/fff_proxy/certs/rootCA.pem", \
     "--host", "0.0.0.0"]
