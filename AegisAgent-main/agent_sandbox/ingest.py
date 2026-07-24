from __future__ import annotations

import os
import shutil
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .constants import MAX_EXTRACTED_BYTES, MAX_FILES, MAX_ZIP_BYTES


class IngestError(ValueError):
    pass


@dataclass
class IngestResult:
    source_zip: Path
    extract_dir: Path
    root_dir: Path
    file_count: int
    total_bytes: int
    warnings: list[str]


def safe_extract_zip(zip_path: Path, workspace: Path) -> IngestResult:
    if zip_path.stat().st_size > MAX_ZIP_BYTES:
        raise IngestError(f"Zip is too large. Limit is {MAX_ZIP_BYTES} bytes.")
    extract_dir = workspace / "source"
    if extract_dir.exists():
        safe_rmtree(extract_dir)
    extract_dir.mkdir(parents=True)
    warnings: list[str] = []
    total = 0
    count = 0
    try:
        with zipfile.ZipFile(zip_path) as archive:
            infos = archive.infolist()
            if not infos:
                raise IngestError("Zip archive is empty.")
            if len(infos) > MAX_FILES:
                raise IngestError(f"Zip contains too many files. Limit is {MAX_FILES}.")
            for info in infos:
                name = info.filename.replace("\\", "/")
                if not name or name.startswith("/") or ".." in Path(name).parts:
                    raise IngestError(f"Unsafe path in zip: {info.filename}")
                mode = (info.external_attr >> 16) & 0o170000
                if mode == 0o120000:
                    warnings.append(f"Skipped symlink-like entry: {info.filename}")
                    continue
                if info.file_size < 0:
                    raise IngestError(f"Invalid file size for {info.filename}")
                total += info.file_size
                if total > MAX_EXTRACTED_BYTES:
                    raise IngestError(f"Extracted content exceeds {MAX_EXTRACTED_BYTES} bytes.")
                target = (extract_dir / name).resolve()
                if not _is_relative_to(target, extract_dir.resolve()):
                    raise IngestError(f"Unsafe extraction target: {info.filename}")
                if name.endswith("/"):
                    os.makedirs(_fs_path(target), exist_ok=True)
                    continue
                os.makedirs(_fs_path(target.parent), exist_ok=True)
                with archive.open(info) as src, open(_fs_path(target), "wb") as dst:
                    shutil.copyfileobj(src, dst)
                count += 1
    except zipfile.BadZipFile as exc:
        raise IngestError("Uploaded file is not a valid zip archive.") from exc
    root = _find_project_root(extract_dir)
    return IngestResult(zip_path, extract_dir, root, count, total, warnings)


def _find_project_root(extract_dir: Path) -> Path:
    children = [child for child in extract_dir.iterdir() if child.name not in {".DS_Store", "__MACOSX"}]
    if len(children) == 1 and children[0].is_dir():
        return children[0]
    return extract_dir


def _fs_path(path: Path) -> str:
    value = str(path)
    if os.name != "nt":
        return value
    if value.startswith("\\\\?\\"):
        return value
    if value.startswith("\\\\"):
        return "\\\\?\\UNC\\" + value[2:]
    return "\\\\?\\" + value


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        pass
    path_text = _strip_extended_prefix(str(path))
    root_text = _strip_extended_prefix(str(root))
    try:
        return os.path.commonpath([os.path.normcase(path_text), os.path.normcase(root_text)]) == os.path.normcase(root_text)
    except ValueError:
        return False


def _strip_extended_prefix(value: str) -> str:
    if value.startswith("\\\\?\\UNC\\"):
        return "\\\\" + value[8:]
    if value.startswith("\\\\?\\"):
        return value[4:]
    return value


def safe_rmtree(path: Path) -> None:
    if not path.exists():
        return
    shutil.rmtree(_fs_path(path))
