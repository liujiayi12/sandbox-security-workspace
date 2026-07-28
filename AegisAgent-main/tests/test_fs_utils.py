from __future__ import annotations

from pathlib import Path

from agent_sandbox.fs_utils import safe_project_copytree, safe_walk_files


def test_safe_project_copytree_skips_generated_dependency_dirs(tmp_path: Path) -> None:
    source = tmp_path / "source"
    dest = tmp_path / "runtime"
    (source / "src").mkdir(parents=True)
    (source / "src" / "agent.py").write_text("print('ok')\n", encoding="utf-8")
    (source / "build").mkdir()
    (source / "build" / "artifact.js").write_text("generated\n", encoding="utf-8")
    (source / "node_modules" / "pkg").mkdir(parents=True)
    (source / "node_modules" / "pkg" / "index.js").write_text("generated\n", encoding="utf-8")
    (source / "target").mkdir()
    (source / "target" / "debug.bin").write_text("generated\n", encoding="utf-8")

    warnings = safe_project_copytree(source, dest)

    assert (dest / "src" / "agent.py").exists()
    assert not (dest / "build").exists()
    assert not (dest / "node_modules").exists()
    assert not (dest / "target").exists()
    assert {item["path"] for item in warnings} >= {"build", "node_modules", "target"}


def test_safe_walk_files_skips_generated_dirs_and_reports_warnings(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("print('ok')\n", encoding="utf-8")
    (tmp_path / "target").mkdir()
    (tmp_path / "target" / "generated.rs").write_text("fn main() {}\n", encoding="utf-8")

    files, warnings = safe_walk_files(tmp_path)

    assert [path.name for path in files] == ["main.py"]
    assert warnings
    assert warnings[0]["path"] == "target"
