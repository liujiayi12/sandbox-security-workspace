# Sandbox Security Workspace

This workspace contains an independent frontend plus two local sandbox backends:

- `sandbox-console`: React/Vite frontend for security users.
- `AegisAgent-main`: Agent sandbox backend, exposed on `http://127.0.0.1:8000`.
- `clawguard-main`: Skill dynamic sandbox backend API, exposed on `http://127.0.0.1:8787`.

## What To Commit

Commit source code, docs, lockfiles, and startup scripts. Do not commit local virtual environments, `node_modules`, Docker installers, build outputs, runtime artifacts, or `.env` files.

The root `.gitignore` is set up to keep those local files on disk while excluding them from Git.

## Local Startup

Start the Agent sandbox:

```powershell
D:\ai_agent\start-aegisagent.ps1
```

Start the Skill dynamic sandbox API:

```powershell
D:\ai_agent\start-skill-dynamic-api.ps1
```

Start the independent frontend:

```powershell
cd D:\ai_agent\sandbox-console
npm.cmd install
npm.cmd run dev
```

Open:

```text
http://127.0.0.1:5174
```

## Docker

Docker Desktop is required for real dynamic sandbox execution. Verify it with:

```powershell
docker run --rm --pull=never hello-world
```

The Skill sandbox image can be prebuilt with:

```powershell
cd D:\ai_agent\clawguard-main\provloom
$env:DOCKER_BUILDKIT=0
docker build --pull=false -t skill-runtime-sandbox:latest -f docker/sandbox/Dockerfile .
```

## LLM Keys

LLM keys are optional. Basic sandbox detection can run without them. If LLM-assisted analysis is needed, provide keys through the UI or backend environment variables. Never commit real keys.
