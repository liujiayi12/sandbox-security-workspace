from __future__ import annotations

import os
import shutil
import stat
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


GENERATED_DIR_NAMES = {
    ".cache",
    ".git",
    ".gradle",
    ".idea",
    ".mypy_cache",
    ".next",
    ".nuxt",
    ".pytest_cache",
    ".ruff_cache",
    ".turbo",
    ".venv",
    ".vscode",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "out",
    "target",
    "venv",
}


@dataclass
class FileSystemWarning:
    stage: str
    path: str
    reason: str
    action: str = "skipped"

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def safe_project_copytree(source: Path, destination: Path, *, skip_generated: bool = True) -> list[dict[str, str]]:
    warnings: list[FileSystemWarning] = []
    source = source.resolve()
    destination = destination.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    _copy_dir(source, destination, source, warnings, skip_generated=skip_generated)
    return [warning.to_dict() for warning in warnings]


def safe_walk_files(root: Path, *, limit: int | None = None, skip_generated: bool = True) -> tuple[list[Path], list[dict[str, str]]]:
    warnings: list[FileSystemWarning] = []
    files: list[Path] = []
    root = root.resolve()
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir(), key=lambda item: item.name.lower())
        except OSError as exc:
            warnings.append(_warning("walk", current, root, exc, "skipped_directory"))
            continue
        for entry in entries:
            try:
                if _is_special_entry(entry):
                    warnings.append(_warning("walk", entry, root, "symlink_or_reparse_point", "skipped_special_entry"))
                    continue
                if entry.is_dir():
                    if skip_generated and _is_generated_dir(entry):
                        warnings.append(_warning("walk", entry, root, "generated_or_dependency_directory", "skipped_directory"))
                        continue
                    stack.append(entry)
                    continue
                if entry.is_file():
                    files.append(entry)
                    if limit is not None and len(files) >= limit:
                        return files, [warning.to_dict() for warning in warnings]
            except OSError as exc:
                warnings.append(_warning("walk", entry, root, exc, "skipped_entry"))
    return files, [warning.to_dict() for warning in warnings]


def safe_walk_file_iter(root: Path, *, limit: int | None = None, skip_generated: bool = True) -> Iterable[Path]:
    files, _warnings = safe_walk_files(root, limit=limit, skip_generated=skip_generated)
    return files


def _copy_dir(source: Path, destination: Path, root: Path, warnings: list[FileSystemWarning], *, skip_generated: bool) -> None:
    try:
        entries = sorted(source.iterdir(), key=lambda item: item.name.lower())
    except OSError as exc:
        warnings.append(_warning("copy", source, root, exc, "skipped_directory"))
        return
    for entry in entries:
        target = destination / entry.name
        try:
            if _is_special_entry(entry):
                warnings.append(_warning("copy", entry, root, "symlink_or_reparse_point", "skipped_special_entry"))
                continue
            if entry.is_dir():
                if skip_generated and _is_generated_dir(entry):
                    warnings.append(_warning("copy", entry, root, "generated_or_dependency_directory", "skipped_directory"))
                    continue
                target.mkdir(parents=True, exist_ok=True)
                _copy_dir(entry, target, root, warnings, skip_generated=skip_generated)
                continue
            if entry.is_file():
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(_fs_path(entry), _fs_path(target))
        except OSError as exc:
            warnings.append(_warning("copy", entry, root, exc, "skipped_entry"))


def _is_generated_dir(path: Path) -> bool:
    return path.name in GENERATED_DIR_NAMES


def _is_special_entry(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        info = path.stat(follow_symlinks=False)
    except OSError:
        raise
    attrs = getattr(info, "st_file_attributes", 0)
    return bool(attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _warning(stage: str, path: Path, root: Path, reason: object, action: str) -> FileSystemWarning:
    return FileSystemWarning(stage=stage, path=_relative_or_name(path, root), reason=str(reason)[:240], action=action)


def _relative_or_name(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        return path.name


def _fs_path(path: Path) -> str:
    value = str(path)
    if os.name != "nt":
        return value
    if value.startswith("\\\\?\\"):
        return value
    if value.startswith("\\\\"):
        return "\\\\?\\UNC\\" + value[2:]
    return "\\\\?\\" + value
