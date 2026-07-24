# AegisAgent 5.0

AegisAgent is a backend-first AI agent sandbox kernel. It accepts a GitHub-style agent zip, performs static risk scanning, discovers candidate runtime plans, attempts Docker-based dynamic execution, runs controlled default attack probes, and returns a risk report.

The 5.0 focus is layered agent adaptation and evaluation: AegisAgent combines evidence-driven BuildPlan discovery, local reserve image diagnostics, runtime API-key aliasing, cross-language interface discovery, OpenAPI-backed HTTP probing, stateful fake environments, and managed real-service substitutes so more agents can be built, launched, attacked, and explained inside the sandbox.

## Core Ideas

- Evidence-driven BuildPlan discovery from `sandbox.yaml`, Dockerfile, devcontainer, Nix, `package.json`, `pyproject.toml`, lockfiles, `langgraph.json`, MCP config, and README-style command hints.
- Multiple candidates per upload. One failed candidate does not stop the dynamic run; the sandbox keeps trying the next plan.
- Docker image build cache for dependency environments.
- Runtime secrets are injected only at runtime, never during dependency build.
- Optional LLM support for audit, attack planning, and BuildPlan suggestions. Without an API key, AegisAgent still uses rule-based discovery and default attacks.
- Controlled attack DSL only. LLM output is never executed as arbitrary shell.

## Requirements

- Python 3.11 or newer.
- Docker Desktop or Docker Engine for dynamic sandbox execution. Without Docker,
  AegisAgent still supports upload, extraction, static scanning, report
  generation, and evaluation code paths that do not require runtime execution.
- Git is optional for ordinary use, but useful when testing agents that depend on
  Git metadata or Git-based workflows.

## Quick Start

Windows PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/setup.ps1
.\.venv\Scripts\python.exe -m agent_sandbox
```

Linux/macOS:

```bash
bash scripts/setup.sh
.venv/bin/python -m agent_sandbox
```

Open `http://127.0.0.1:8000`.

The first screen is the upload UI. It accepts an agent zip, optional model/API
settings, LLM-assistance toggles, network policy, build policy, and whether to
delete first-level build images after the run. The UI renders a user-facing
Markdown report after completion and can download the same report as `.md`.

## Manual Start

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
.\.venv\Scripts\python -m agent_sandbox --reload
```

Open `http://127.0.0.1:8000` for the web UI or
`http://127.0.0.1:8000/docs` for the API docs.

## Optional Image Setup

AegisAgent can run with official public base images, but dynamic compatibility
is better when the second-layer reserve images are available locally.

Build all enhanced images:

```powershell
powershell -ExecutionPolicy Bypass -File docker/images/scripts/build.ps1
```

Or install dependencies and build images in one step:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/setup.ps1 -BuildImages
```

## API

- `POST /api/runs`: upload a zip. Required form field: `file`.
- `GET /api/runs/{id}`: run status.
- `GET /api/runs/{id}/events`: install/start/probe/attack logs.
- `GET /api/runs/{id}/report`: full report.

Optional `POST /api/runs` form fields:

- `providers`: JSON array of LLM providers for sandbox-side audit/planning.
- `runtime_env`: JSON object of environment variables for the tested agent.
- `runtime_network`: `auto`, `none`, or `bridge`; default `auto`. In auto mode, runtime model credentials or provider base URLs enable `bridge`, otherwise runtime remains `none`.
- `build_mode`: `auto`, `strict`, or `sandbox_yaml_only`; default `auto`.
- `allow_install_scripts`: default `true`.
- `cache_policy`: `use`, `rebuild`, or `disabled`; default `use`.
- `delete_build_image_after_run`: `true` deletes only first-level `agent-sandbox-build:*` images created or reused by this run after dynamic testing; default `false`. It never deletes protected second-level `aegisagent-*` reserve images.

Example `providers`:

```json
[
  {
    "provider": "deepseek",
    "base_url": "https://api.deepseek.com/v1",
    "api_key": "sk-...",
    "model": "deepseek-chat",
    "role": "audit"
  }
]
```

Example `runtime_env`:

```json
{
  "OPENAI_API_KEY": "sk-...",
  "OPENAI_API_BASE_URL": "https://api.openai.com/v1",
  "OPENAI_BASE_URL": "https://api.openai.com/v1",
  "MODEL_NAME": "gpt-4o-mini",
  "SILICONFLOW_API_KEY": "sk-...",
  "SILICONFLOW_BASE_URL": "https://api.siliconflow.cn/v1",
  "SILICONFLOW_MODEL": "deepseek-ai/DeepSeek-V3"
}
```

## Local `.env`

Sandbox-side LLM settings:

```env
SANDBOX_LLM_PROVIDER=deepseek
SANDBOX_LLM_BASE_URL=https://api.deepseek.com/v1
SANDBOX_LLM_MODEL=deepseek-chat
SANDBOX_LLM_API_KEY=your-key
```

Tested-agent runtime settings:

```env
SANDBOX_RUNTIME_OPENAI_API_KEY=your-runtime-key
SANDBOX_RUNTIME_OPENAI_API_BASE_URL=https://api.openai.com/v1
SANDBOX_RUNTIME_OPENAI_BASE_URL=https://api.openai.com/v1
SANDBOX_RUNTIME_MODEL_NAME=gpt-4o-mini
SANDBOX_RUNTIME_SILICONFLOW_API_KEY=your-runtime-key
SANDBOX_RUNTIME_SILICONFLOW_BASE_URL=https://api.siliconflow.cn/v1
SANDBOX_RUNTIME_SILICONFLOW_MODEL=deepseek-ai/DeepSeek-V3
SANDBOX_RUNTIME_NETWORK=auto
```

`SANDBOX_LLM_*` is for AegisAgent itself. `SANDBOX_RUNTIME_*` is for the untrusted agent being tested.

## Dynamic Runtime

When Docker is available, AegisAgent builds or reuses a local image and runs candidates with hardened runtime flags:

- `--network=none` by default, or `--network=bridge` when `runtime_network=bridge` is explicit or `runtime_network=auto` detects runtime provider credentials
- `--cap-drop=ALL`
- `--security-opt=no-new-privileges`
- `--pids-limit=256`
- `--memory=768m` by default; JVM/Java HTTP candidates use `--memory=2g`
- `--cpus=1`

The dependency build stage may use network access, but runtime API keys are not injected into build containers. Runtime network access requires explicit `runtime_network=bridge`.

## Fake Environment Layers

AegisAgent's fake environment has three layers:

- Layer 1: protocol-level fake APIs for OpenAI-compatible models, web/search, email, GitHub, Slack, calendar, drive, RAG, MCP, webhook sink, and event collection.
- Layer 2: state-machine simulation. The fake environment records external objects, external content reads, browser page visits, active multi-surface scenarios, state changes, permission-scope violations, canary movement, and audit events through `/state`, `/audit`, and `/scenarios`.
- Layer 3: optional real local service integration. The fake environment can register and proxy local services through `/real/services` and `/real/{service}/...`.

Default runs stay lightweight: Layer 3 service plans are generated, but large real-service containers are not started unless explicitly requested.
Every run also writes real-service fixture manifests under `.agent_sandbox/fake_env/fixtures/real_services` and multi-surface scenario manifests under `.agent_sandbox/fake_env/scenarios`. These manifests describe seeded malicious emails, repository issues, RAG/object-store documents, browser pages, cross-service task chains, and credentials that future service initializers can replay into managed services.
When a managed email preset such as `mailhog` or `mailpit` is enabled, AegisAgent attempts to inject the email fixture through SMTP and records the result in `.agent_sandbox/fake_env/real_service_init.json`. When `minio` is enabled, AegisAgent attempts to create the fixture bucket and upload the poisoned object through the S3-compatible API. When `gitea` is enabled, AegisAgent attempts to seed repository issues and files through the Gitea API. When `playwright` is enabled, AegisAgent attempts to connect to the managed browser service and visit the malicious page fixtures through a real browser context.

Useful runtime URLs injected into tested agents when `runtime_network=sandbox`:

- `AGENT_SANDBOX_FAKE_BASE_URL`
- `AGENT_SANDBOX_SINK_URL`
- `AGENT_SANDBOX_STATE_URL`
- `AGENT_SANDBOX_AUDIT_URL`
- `AGENT_SANDBOX_EPISODES_URL`
- `AGENT_SANDBOX_SCENARIOS_URL`
- `AGENT_SANDBOX_REAL_SERVICES_URL`
- `AGENT_SANDBOX_REAL_SERVICE_PLAN_URL`
- `AGENT_SANDBOX_REAL_FIXTURES_URL`
- `AGENT_SANDBOX_REAL_SCENARIOS_URL`

Enable managed real-service presets with:

```powershell
$env:AGENT_SANDBOX_REAL_SERVICES = "mailhog,minio,gitea,playwright"
```

Available presets are currently `mailhog`, `mailpit`, `minio`, `gitea`, and `playwright`. They are attached to the sandbox-private Docker network and exposed to the fake environment through controlled internal aliases such as `http://agent-sandbox-real-mailhog:8025`.

The same mechanism can proxy manually managed local services by writing `.agent_sandbox/fake_env/real_services.json`:

```json
{
  "services": [
    {
      "name": "demo",
      "kind": "http",
      "base_url": "http://host.docker.internal:8080",
      "health_path": "/health",
      "allowed_prefixes": ["/api/"]
    }
  ]
}
```

Only local or sandbox-managed service addresses are accepted; the fake environment does not act as a public internet proxy.

## Image Reserve

AegisAgent uses a three-tier image reserve:

- Light official images for minimal builds.
- Enhanced local AegisAgent images with common native build dependencies.
- A universal Dev Containers based fallback for broad multi-language projects.

Enhanced images live under `docker/images` and can be built locally:

```powershell
powershell -ExecutionPolicy Bypass -File docker/images/scripts/build.ps1
```

Build only the Rust image:

```powershell
powershell -ExecutionPolicy Bypass -File docker/images/scripts/build.ps1 -Name rust
```

Important tags:

- `aegisagent-python:3.12-bookworm`
- `aegisagent-node:22-bookworm`
- `aegisagent-go:1.24-bookworm`
- `aegisagent-rust:1-bookworm`
- `aegisagent-java:21-bookworm`
- `aegisagent-universal:linux`

If an enhanced image is not present locally, AegisAgent falls back to the corresponding official image and records that in the BuildPlan reason.
Each generated BuildPlan also includes an `image_resolution` object with the requested image, selected image, selected layer, local reserve candidates, cached public fallback candidates, and whether a public pull is still required.

You can inspect the current second-layer reserve status without pulling images:

```powershell
curl http://127.0.0.1:8000/api/image-reserve
```

## Reports

Reports include:

- Whether dynamic execution completed.
- Detected languages, frameworks, protocols, and candidate plans.
- Build status, cache hit, BuildPlan, BuildResult, and failure class.
- Default attack plan and observed evidence.
- Canary hits, file diffs, network intent, and runtime API-key requirements.
- Separate handling for sandbox failures and tested-agent application errors.

## Vulnerability Discovery Evaluation

AegisAgent includes a structured evaluation runner for measuring vulnerability discovery rather than ordinary upload success. Evaluation cases live as JSON/JSONL manifests with `agent_name`, `version_or_commit`, `vulnerability_type`, optional `trigger_path`, expected evidence, and expected report signals.

Run a case set:

```powershell
python -m agent_sandbox.evaluation --cases eval_cases/examples.json --samples-root examples/eval_samples --workspace .sandbox_data/eval_runs
```

Evaluation results are separated by work mode:

- `baseline_static`: no LLM and no dynamic sandbox.
- `baseline_dynamic`: no LLM; default dynamic attacks, fake environment, canaries, and sink evidence.
- `llm_assisted`: controlled LLM support for static audit, BuildPlan candidates, dynamic attack planning, artifact variants, and report explanation.
- `targeted_oracle`: known-vulnerability reproduction with case-provided trigger paths.

Do not merge these into one score. Use the no-LLM baseline for sandbox hard capability, LLM-assisted results for product-mode uplift, and targeted/oracle results for known-vulnerability reproduction. See `docs/evaluation.md`.

## Real Samples And Research

Third-party sample archives, downloaded mainstream-agent corpora, expanded
research repositories, Docker data disks, and first-level build images are
intentionally not committed. They can easily reach multiple GB and may contain
third-party code with separate licenses.

The public repository keeps:

- AegisAgent source code and web UI.
- Dockerfile templates for second-layer reserve images.
- Tests and lightweight evaluation examples.
- Documentation for recreating local samples and image reserves.

Local-only directories ignored by Git include `real_samples/`,
`research_repos/`, `.sandbox_data/`, `.venv/`, and generated build/test caches.
See `SOURCES.md` for URLs and local material notes.
