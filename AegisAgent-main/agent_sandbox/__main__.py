from __future__ import annotations

import argparse
import os
from pathlib import Path

import uvicorn


def main() -> None:
    docker_cli_dir = Path(r"C:\Program Files\Docker\Docker\resources\bin")
    if os.name == "nt" and docker_cli_dir.exists():
        current_path = os.environ.get("PATH", "")
        parts = [part for part in current_path.split(os.pathsep) if part]
        if str(docker_cli_dir).lower() not in {part.lower() for part in parts}:
            os.environ["PATH"] = os.pathsep.join([str(docker_cli_dir), *parts])

    parser = argparse.ArgumentParser(description="Run the AegisAgent web/API server.")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind.")
    parser.add_argument("--port", default=8000, type=int, help="Port to bind.")
    parser.add_argument("--reload", action="store_true", help="Enable uvicorn reload for development.")
    args = parser.parse_args()
    uvicorn.run("agent_sandbox.main:app", host=args.host, port=args.port, reload=args.reload)


if __name__ == "__main__":
    main()
