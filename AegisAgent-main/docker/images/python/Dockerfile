FROM python:3.12-bookworm

ENV PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1

RUN set -eux; \
    sed -i \
      -e 's|http://deb.debian.org/debian|http://mirrors.aliyun.com/debian|g' \
      -e 's|http://security.debian.org/debian-security|http://mirrors.aliyun.com/debian-security|g' \
      /etc/apt/sources.list.d/debian.sources; \
    apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    cmake \
    curl \
    ffmpeg \
    git \
    libasound2 \
    libffi-dev \
    libgbm1 \
    libgl1 \
    libglib2.0-0 \
    libgtk-3-0 \
    libjpeg-dev \
    libnss3 \
    libpq-dev \
    libsqlite3-dev \
    libssl-dev \
    libxml2-dev \
    libxslt1-dev \
    pkg-config \
    portaudio19-dev \
    protobuf-compiler \
    python3-dev \
    libsndfile1-dev \
    sqlite3 \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python -m pip install --upgrade pip setuptools wheel uv poetry
