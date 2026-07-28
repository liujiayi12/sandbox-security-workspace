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

## Docker Registry Mirrors

The image build script does not change Docker Desktop or Docker Engine daemon
settings. If base-image pulls are slow, configure `registry-mirrors` in Docker
first, then run the build script.

Docker Desktop on Windows:

1. Open Docker Desktop.
2. Go to Settings -> Docker Engine.
3. Add or merge a `registry-mirrors` array.
4. Apply and restart Docker Desktop.

Example shape:

```json
{
  "registry-mirrors": [
    "https://your-reachable-docker-mirror.example"
  ]
}
```

Linux Docker Engine:

```bash
sudo mkdir -p /etc/docker
sudo tee /etc/docker/daemon.json >/dev/null <<'JSON'
{
  "registry-mirrors": [
    "https://your-reachable-docker-mirror.example"
  ]
}
JSON
sudo systemctl restart docker
```

After changing the mirror, verify a normal pull:

```powershell
docker pull python:3.12-bookworm
docker pull node:22-bookworm
```

Use a mirror that is reachable in your own network. Mirror availability changes,
so avoid hard-coding an unavailable mirror into shared scripts.
