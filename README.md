# ASGuard

ASGuard is a local security testing workspace for AI Skills and AI Agents. It provides a standalone React/Vite console and connects two local backend services:

- Skill dynamic sandbox service, based on the ProvLoom capability in `clawguard-main`
- Agent sandbox analysis service, based on `AegisAgent-main`

The platform supports sample upload, strategy configuration, isolated execution, behavior observation, risk scoring, and report display.

## Project Structure

```text
.
├── sandbox-console/              # ASGuard frontend console
├── AegisAgent-main/              # Agent sandbox backend
├── clawguard-main/               # Skill sandbox backend and related services
├── start-frontend.ps1            # Start ASGuard frontend
├── start-aegisagent.ps1          # Start Agent sandbox backend
├── start-skill-dynamic-api.ps1   # Start Skill sandbox API
└── README.md
```

## Core Features

### Frontend Console

The `sandbox-console` application is the unified ASGuard user interface. It provides:

- Login and session state
- Security overview
- Skill detection workspace
- Agent analysis workspace
- Admin invite-code management
- Backend service status checks
- Markdown report and raw JSON result display

### Skill Dynamic Sandbox

The Skill backend supports `SKILL.md`, Skill zip packages, and remote Skill URLs. It runs samples in an isolated environment and records file, process, network, tool-call, and LLM-related behavior.

Main capabilities:

- Standard, isolated, and quick detection strategies
- Runtime behavior observation
- Risk score and risk level generation
- Evidence timeline and behavior-chain display
- Markdown report and JSON detail output

### Agent Sandbox Analysis

The Agent backend accepts complete Agent project zip packages. It performs project extraction, structure discovery, static scanning, build-plan discovery, Docker-based dynamic execution, attack probing, and report generation.

Main capabilities:

- Agent project upload
- Dependency and entrypoint discovery
- Docker sandbox execution
- Runtime event collection
- Risk report generation

## Local Setup

Local dependency directories such as `.venv`, `node_modules`, `.npm-cache`, runtime caches, `.env`, and build outputs are ignored by Git and should not be committed.

### 1. Install Agent Backend Dependencies

```powershell
cd .\AegisAgent-main
powershell -ExecutionPolicy Bypass -File scripts\setup.ps1
cd ..
```

### 2. Install Skill Backend Dependencies

```powershell
cd .\clawguard-main\web
npm.cmd install
cd ..\..
```

### 3. Install Frontend Dependencies

```powershell
cd .\sandbox-console
npm.cmd install
cd ..
```

## Start Services

Start the three services in separate PowerShell windows.

### Agent Sandbox Backend

```powershell
.\start-aegisagent.ps1
```

Default URL:

```text
http://127.0.0.1:8000
```

### Skill Dynamic Sandbox Backend

```powershell
.\start-skill-dynamic-api.ps1
```

Default URL:

```text
http://127.0.0.1:8787
```

### ASGuard Frontend

```powershell
.\start-frontend.ps1
```

Default URL:

```text
http://127.0.0.1:5174
```

## Docker Requirement

Dynamic sandbox execution depends on Docker Desktop or Docker Engine. Verify Docker before running sandbox tasks:

```powershell
docker run --rm hello-world
```

The Skill sandbox image can be built manually when needed:

```powershell
cd .\clawguard-main\provloom
$env:DOCKER_BUILDKIT=0
docker build --pull=false -t skill-runtime-sandbox:latest -f docker/sandbox/Dockerfile .
```

## Notes For GitHub

Do not commit local runtime or dependency artifacts:

- `.env`
- `.venv`
- `node_modules`
- `.npm-cache`
- `runtime-cache`
- build outputs
- local databases and logs

The repository should contain source code, lock files, requirements files, startup scripts, and documentation only.
