from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from agent_sandbox.constants import MAX_FILES
from agent_sandbox.ingest import IngestError, _fs_path, _is_relative_to, safe_extract_zip, safe_rmtree


def test_safe_extract_rejects_path_traversal(tmp_path: Path) -> None:
    zip_path = tmp_path / "bad.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("../evil.txt", "bad")

    with pytest.raises(IngestError):
        safe_extract_zip(zip_path, tmp_path / "work")


def test_safe_extract_finds_single_root(tmp_path: Path) -> None:
    zip_path = tmp_path / "agent.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("repo/main.py", "print('hi')")

    result = safe_extract_zip(zip_path, tmp_path / "work")

    assert result.file_count == 1
    assert result.root_dir.name == "repo"


def test_safe_extract_handles_long_paths(tmp_path: Path) -> None:
    zip_path = tmp_path / "long-path.zip"
    long_name = "please-do-not-open-an-issue-here--instead--open-an-issue-in-the-main-repository--https---github-com-example-example-issues-new-choose.md"
    member = f"repo/.github/ISSUE_TEMPLATE/{long_name}"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr(member, "template")

    result = safe_extract_zip(zip_path, tmp_path / ("work-" + "x" * 80))

    assert result.file_count == 1
    extracted = result.root_dir / ".github" / "ISSUE_TEMPLATE" / long_name
    with open(_fs_path(extracted), encoding="utf-8") as handle:
        assert handle.read() == "template"
    safe_rmtree(result.extract_dir)
    assert not result.extract_dir.exists()


def test_safe_extract_allows_paths_with_same_prefix_as_workspace(tmp_path: Path) -> None:
    zip_path = tmp_path / "agent.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("repo/examples/evaluation/callbacks/output/math-eval-app/result.json", "{}")

    result = safe_extract_zip(zip_path, tmp_path / "work")

    assert (result.root_dir / "examples" / "evaluation" / "callbacks" / "output" / "math-eval-app" / "result.json").exists()


def test_safe_extract_allows_common_monorepo_file_counts(tmp_path: Path) -> None:
    assert MAX_FILES >= 10000
    zip_path = tmp_path / "monorepo.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        for index in range(6500):
            archive.writestr(f"repo/packages/pkg_{index}/README.md", "ok")

    result = safe_extract_zip(zip_path, tmp_path / "work")

    assert result.file_count == 6500


def test_relative_check_accepts_windows_extended_prefix() -> None:
    root = Path(r"D:\workspace\source")
    target = Path(r"\\?\D:\workspace\source\repo\very-long-file.json")

    assert _is_relative_to(target, root) is True
