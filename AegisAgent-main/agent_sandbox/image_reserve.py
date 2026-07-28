from __future__ import annotations

import os


PYTHON_311 = "aegisagent-python:3.12-bookworm"
PYTHON_312 = "aegisagent-python:3.12-bookworm"
PYTHON_310_SLIM = "python:3.10-slim"
NODE_22 = "aegisagent-node:22-bookworm"
BUN_1 = "oven/bun:1"
GO_124 = "aegisagent-go:1.24-bookworm"
GO_125 = "aegisagent-go:1.25-bookworm"
RUST_1 = "aegisagent-rust:1-bookworm"
JAVA_21 = "aegisagent-java:21-bookworm"
UNIVERSAL = "aegisagent-universal:linux"
SHELL_BASH = "bash:5.2"

OFFICIAL_IMAGES = {
    "python": "python:3.12-slim",
    "node": "node:22-bookworm",
    "bun": BUN_1,
    "go": "golang:1.25-bookworm",
    "rust": "rust:1-bookworm",
    "java": "maven:3.9-eclipse-temurin-21",
    "universal": "mcr.microsoft.com/devcontainers/universal:linux",
    "shell": SHELL_BASH,
}

MIRROR_IMAGES = {
    "python": "m.daocloud.io/docker.io/library/python:3.12-slim",
    "node": "m.daocloud.io/docker.io/library/node:22-bookworm",
    "bun": "m.daocloud.io/docker.io/oven/bun:1",
    "go": "m.daocloud.io/docker.io/library/golang:1.25-bookworm",
    "rust": "m.daocloud.io/docker.io/library/rust:1-bookworm",
    "java": "m.daocloud.io/docker.io/library/maven:3.9-eclipse-temurin-21",
    "universal": "m.daocloud.io/mcr.microsoft.com/devcontainers/universal:linux",
    "shell": "m.daocloud.io/docker.io/library/bash:5.2",
}

DOCKERHUB_MIRROR_PREFIXES = [
    "m.daocloud.io/docker.io",
    "docker.1ms.run",
    "hub.rat.dev",
    "dockerproxy.net",
]

DOCKER_REGISTRY_MIRRORS = [
    "https://docker.1ms.run",
    "https://docker.m.daocloud.io",
    "https://hub.rat.dev",
    "https://dockerproxy.net",
]


def _configured_mirror_prefixes() -> list[str]:
    raw = os.getenv("AGENT_SANDBOX_IMAGE_MIRROR_PREFIXES", "")
    prefixes = [item.strip().rstrip("/") for item in raw.split(",") if item.strip()]
    return prefixes or DOCKERHUB_MIRROR_PREFIXES


def _has_configured_mirror_prefixes() -> bool:
    return bool(os.getenv("AGENT_SANDBOX_IMAGE_MIRROR_PREFIXES", "").strip())


def dockerhub_mirror_images(repository: str, tag: str, library: bool = True) -> list[str]:
    repo = f"library/{repository}" if library else repository
    return [f"{prefix}/{repo}:{tag}" for prefix in _configured_mirror_prefixes()]


def _ordered_public_images(kind: str, mirrors: list[str]) -> list[str]:
    official = OFFICIAL_IMAGES[kind]
    mirrors = [image for image in mirrors if image != official]
    if _has_configured_mirror_prefixes():
        return [*mirrors, official]
    return [official, *mirrors]


LOCAL_RESERVE_IMAGES = {
    "python": [PYTHON_312, PYTHON_311, PYTHON_310_SLIM],
    "node": [NODE_22],
    "bun": [BUN_1],
    "go": [GO_125, GO_124],
    "rust": [RUST_1],
    "java": [JAVA_21],
    "shell": [UNIVERSAL, SHELL_BASH, PYTHON_310_SLIM],
    "custom": [UNIVERSAL, PYTHON_310_SLIM],
}

PUBLIC_FALLBACK_IMAGES = {
    "python": _ordered_public_images("python", dockerhub_mirror_images("python", "3.12-slim")),
    "node": _ordered_public_images("node", dockerhub_mirror_images("node", "22-bookworm")),
    "bun": _ordered_public_images("bun", dockerhub_mirror_images("oven/bun", "1", library=False)),
    "go": _ordered_public_images("go", dockerhub_mirror_images("golang", "1.25-bookworm")),
    "rust": _ordered_public_images("rust", dockerhub_mirror_images("rust", "1-bookworm")),
    "java": _ordered_public_images("java", dockerhub_mirror_images("maven", "3.9-eclipse-temurin-21")),
    "shell": _ordered_public_images("shell", dockerhub_mirror_images("bash", "5.2")),
    "custom": _ordered_public_images("universal", [MIRROR_IMAGES["universal"]]),
}
