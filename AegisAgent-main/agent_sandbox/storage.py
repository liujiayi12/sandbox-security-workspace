from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init()

    @contextmanager
    def conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def init(self) -> None:
        with self.conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    id TEXT PRIMARY KEY,
                    input_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    dynamic_status TEXT,
                    llm_status TEXT,
                    risk_level TEXT,
                    workspace TEXT NOT NULL,
                    profile_json TEXT,
                    report_json TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    ts TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    level TEXT NOT NULL,
                    message TEXT NOT NULL,
                    data_json TEXT NOT NULL DEFAULT '{}'
                )
                """
            )

    def create_run(self, run_id: str, input_name: str, workspace: Path) -> None:
        now = utc_now()
        with self.conn() as conn:
            conn.execute(
                """
                INSERT INTO runs (id, input_name, status, stage, workspace, created_at, updated_at)
                VALUES (?, ?, 'queued', 'queued', ?, ?, ?)
                """,
                (run_id, input_name, str(workspace), now, now),
            )

    def update_run(self, run_id: str, **fields: Any) -> None:
        if not fields:
            return
        fields["updated_at"] = utc_now()
        keys = list(fields)
        values = [self._to_db(fields[k]) for k in keys]
        assignments = ", ".join(f"{k}=?" for k in keys)
        with self.conn() as conn:
            conn.execute(f"UPDATE runs SET {assignments} WHERE id=?", [*values, run_id])

    def add_event(self, run_id: str, stage: str, level: str, message: str, data: dict[str, Any] | None = None) -> None:
        data = self._redact(data or {})
        with self.conn() as conn:
            conn.execute(
                """
                INSERT INTO events (run_id, ts, stage, level, message, data_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (run_id, utc_now(), stage, level, message, json.dumps(data, ensure_ascii=False)),
            )

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        with self.conn() as conn:
            row = conn.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        return self._row_to_dict(row) if row else None

    def list_events(self, run_id: str) -> list[dict[str, Any]]:
        with self.conn() as conn:
            rows = conn.execute(
                "SELECT ts, stage, level, message, data_json FROM events WHERE run_id=? ORDER BY id ASC",
                (run_id,),
            ).fetchall()
        events = []
        for row in rows:
            item = dict(row)
            item["data"] = json.loads(item.pop("data_json") or "{}")
            events.append(item)
        return events

    def get_report(self, run_id: str) -> dict[str, Any] | None:
        run = self.get_run(run_id)
        if not run or not run.get("report_json"):
            return None
        return json.loads(run["report_json"])

    @staticmethod
    def _to_db(value: Any) -> Any:
        if isinstance(value, (dict, list)):
            return json.dumps(value, ensure_ascii=False)
        return value

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        return {key: row[key] for key in row.keys()}

    @classmethod
    def _redact(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: ("[redacted]" if "key" in key.lower() or "token" in key.lower() or "secret" in key.lower() else cls._redact(val))
                for key, val in value.items()
            }
        if isinstance(value, list):
            return [cls._redact(item) for item in value]
        return value

