# AegisAgent Research And Sample Sources

This repository keeps third-party samples and research archives out of Git. Local copies may exist under `real_samples/` and `research_repos/`, but those directories are intentionally ignored.

## Real Samples

- `modelcontextprotocol/servers`: https://github.com/modelcontextprotocol/servers
  - Used to validate MCP stdio startup and `initialize` / `tools/list` probing.
- `crewAIInc/crewAI-examples`: https://github.com/crewAIInc/crewAI-examples
  - Used to validate CrewAI project detection, dependency construction, and runtime API-key handling.
- `LMescheder/chat`: https://github.com/LMescheder/chat
  - Used to validate Python console-script detection and legacy OpenAI SDK dependency handling.
- `langchain-ai/langgraph-example-monorepo`: https://github.com/langchain-ai/langgraph-example-monorepo
  - Used to validate LangGraph monorepo BuildPlan discovery.

## Research Repositories

- E2B: https://github.com/e2b-dev/E2B
  - Reference for command-oriented sandbox execution and templates.
- Daytona: https://github.com/daytonaio/daytona
  - Reference for declarative images, snapshots, and sandbox command sessions.
- OpenHands: https://github.com/OpenHands/OpenHands
  - Reference for configurable sandbox images and agent-driven environment setup.

## Documentation References

- Daytona Declarative Builder: https://www.daytona.io/docs/en/declarative-builder/
- OpenHands custom sandbox guide: https://docs.openhands.dev/openhands/usage/how-to/custom-sandbox-guide
- Modal Sandboxes: https://modal.com/docs/guide/sandbox
- E2B documentation: https://www.e2b.dev/docs
