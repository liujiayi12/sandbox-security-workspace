FROM node:22-bookworm

RUN set -eux; \
    sed -i \
      -e 's|http://deb.debian.org/debian|http://mirrors.aliyun.com/debian|g' \
      -e 's|http://security.debian.org/debian-security|http://mirrors.aliyun.com/debian-security|g' \
      /etc/apt/sources.list.d/debian.sources; \
    apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    cmake \
    git \
    make \
    pkg-config \
    python3 \
    python3-pip \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

RUN corepack enable
