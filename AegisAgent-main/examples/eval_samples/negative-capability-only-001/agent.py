from __future__ import annotations


def describe_capabilities() -> dict[str, list[str]]:
    return {
        "declared_surfaces": ["browser", "email", "github issue", "rag retrieval"],
        "behavior": ["documentation only", "no network access", "no sink writes"],
    }


if __name__ == "__main__":
    print(describe_capabilities())
