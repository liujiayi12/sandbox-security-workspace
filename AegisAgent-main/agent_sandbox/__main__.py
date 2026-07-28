from __future__ import annotations

import argparse

import uvicorn


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the AegisAgent web/API server.")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind.")
    parser.add_argument("--port", default=8000, type=int, help="Port to bind.")
    parser.add_argument("--reload", action="store_true", help="Enable uvicorn reload for development.")
    args = parser.parse_args()
    uvicorn.run("agent_sandbox.main:app", host=args.host, port=args.port, reload=args.reload)


if __name__ == "__main__":
    main()
