FROM mcr.microsoft.com/devcontainers/universal:linux

RUN set -eux; \
    if [ -f /etc/apt/sources.list.d/ubuntu.sources ]; then \
      sudo sed -i \
        -e 's|http://archive.ubuntu.com/ubuntu/|http://mirrors.aliyun.com/ubuntu/|g' \
        -e 's|http://security.ubuntu.com/ubuntu/|http://mirrors.aliyun.com/ubuntu/|g' \
        /etc/apt/sources.list.d/ubuntu.sources; \
    fi; \
    sudo apt-get update && sudo apt-get install -y --no-install-recommends \
    libasound2-dev \
    libdbus-1-dev \
    libfontconfig1-dev \
    libpq-dev \
    libsqlite3-dev \
    libssl-dev \
    libudev-dev \
    pkg-config \
    protobuf-compiler \
    && sudo rm -rf /var/lib/apt/lists/*
