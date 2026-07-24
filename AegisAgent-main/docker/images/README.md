# AegisAgent Image Reserve

AegisAgent uses a three-tier image reserve:

1. **Light official images**: upstream language images such as `python`, `node`, `golang`, `rust`, and `maven`.
2. **Enhanced AegisAgent images**: local images with common native build dependencies preinstalled.
3. **Universal fallback**: a broad Dev Containers based image for unknown or multi-language projects.

When Docker Hub is unreliable, the runtime planner can fall back to mirrored
public image names such as `m.daocloud.io/docker.io/library/maven:...` before
trying the plain Docker Hub tag.

The enhanced images reduce repeated failures caused by missing native packages such as `pkg-config`, `libdbus-1-dev`, `libssl-dev`, compilers, CMake, and protobuf tooling.

Build all enhanced images:

```powershell
powershell -ExecutionPolicy Bypass -File docker/images/scripts/build.ps1
```

Build one image:

```powershell
powershell -ExecutionPolicy Bypass -File docker/images/scripts/build.ps1 -Name rust
```

Tags:

- `aegisagent-python:3.12-bookworm`
- `aegisagent-node:22-bookworm`
- `aegisagent-go:1.24-bookworm`
- `aegisagent-rust:1-bookworm`
- `aegisagent-java:21-bookworm`
- `aegisagent-universal:linux`

These images are local by default and are intentionally not pushed to a remote registry.
