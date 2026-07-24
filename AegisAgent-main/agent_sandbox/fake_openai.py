from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        self._json({"ok": True, "service": "agent-sandbox-fake-openai"})

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("content-length", "0") or "0")
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        try:
            payload = json.loads(body) if body else {}
        except json.JSONDecodeError:
            payload = {}
        if self.path.endswith("/chat/completions"):
            self._json(
                {
                    "id": "chatcmpl-sandbox",
                    "object": "chat.completion",
                    "created": 0,
                    "model": payload.get("model", "sandbox-fake-model"),
                    "choices": [
                        {
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": "Sandbox fake model response. No external model was contacted.",
                            },
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                }
            )
            return
        if self.path.endswith("/embeddings"):
            inputs = payload.get("input", [])
            count = len(inputs) if isinstance(inputs, list) else 1
            self._json(
                {
                    "object": "list",
                    "data": [{"object": "embedding", "index": idx, "embedding": [0.0] * 8} for idx in range(count)],
                    "model": payload.get("model", "sandbox-fake-embedding"),
                    "usage": {"prompt_tokens": 1, "total_tokens": 1},
                }
            )
            return
        self._json({"ok": True})

    def log_message(self, format: str, *args: object) -> None:
        return

    def _json(self, data: dict) -> None:
        raw = json.dumps(data).encode("utf-8")
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
