FROM mcr.microsoft.com/devcontainers/universal:linux

RUN set -eux; \
    if [ -f /etc/apt/sources.list.d/ubuntu.sources ]; then \
      sudo sed -i \
        -e 's|http://archive.ubuntu.com/ubuntu/|http://mirrors.aliyun.com/ubuntu/|g' \
        -e 's|http://security.ubuntu.com/ubuntu/|http://mirrors.aliyun.com/ubuntu/|g' \
        /etc/apt/sources.list.d/ubuntu.sources; \
    fi; \
    sudo apt-get update && sudo apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    curl \
    ffmpeg \
    libgl1 \
    libglib2.0-0 \
    libgtk-3-0 \
    libnss3 \
    libasound2-dev \
    libdbus-1-dev \
    libfontconfig1-dev \
    libpq-dev \
    libsqlite3-dev \
    libssl-dev \
    libudev-dev \
    pkg-config \
    protobuf-compiler \
    python3 \
    python3-pip \
    unzip \
    && sudo rm -rf /var/lib/apt/lists/*
