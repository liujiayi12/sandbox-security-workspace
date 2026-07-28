FROM maven:3.9-eclipse-temurin-21

RUN set -eux; \
    sed -i \
      -e 's|http://archive.ubuntu.com/ubuntu/|http://mirrors.aliyun.com/ubuntu/|g' \
      -e 's|http://security.ubuntu.com/ubuntu/|http://mirrors.aliyun.com/ubuntu/|g' \
      /etc/apt/sources.list.d/ubuntu.sources; \
    apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    git \
    gradle \
    libsqlite3-dev \
    libssl-dev \
    make \
    pkg-config \
    protobuf-compiler \
    python3 \
    python3-pip \
    unzip \
    && rm -rf /var/lib/apt/lists/*
