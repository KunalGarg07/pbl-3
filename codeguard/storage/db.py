"""Scan history in SQLite.

By default only a SHA-256 of the submitted code is stored, not the code itself
(set CODEGUARD_STORE_SOURCE=true to keep it).
"""
import json
import sqlite3
from contextlib import closing
from pathlib import Path

from codeguard.config import settings
from codeguard.schemas import ScanResult

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id       TEXT PRIMARY KEY,
    created_at    TEXT NOT NULL,
    filename      TEXT NOT NULL,
    language      TEXT NOT NULL,
    source_sha256 TEXT NOT NULL,
    total         INTEGER NOT NULL,
    high_or_worse INTEGER NOT NULL,
    result_json   TEXT NOT NULL,
    source_text   TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at);
CREATE TABLE IF NOT EXISTS explanations (
    cache_key   TEXT PRIMARY KEY,
    created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    result_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS fix_attempts (
    attempt_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT,
    finding_id  TEXT,
    created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status      TEXT NOT NULL,
    result_json TEXT NOT NULL
);
"""


class ScanStore:
    def __init__(self, db_path: Path | str | None = None):
        self.db_path = Path(db_path or settings.db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as conn, conn:
            conn.executescript(SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def save(self, result: ScanResult, source: str | None = None) -> None:
        high = result.summary.by_severity.get("Critical", 0) + result.summary.by_severity.get("High", 0)
        with closing(self._connect()) as conn, conn:
            conn.execute(
                "INSERT OR REPLACE INTO scans VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (result.scan_id, result.created_at.isoformat(), result.filename, result.language,
                 result.source_sha256, result.summary.total, high, result.model_dump_json(), source),
            )

    def list_scans(self, limit: int = 50, offset: int = 0) -> list[dict]:
        with closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT scan_id, created_at, filename, language, total, high_or_worse "
                "FROM scans ORDER BY created_at DESC LIMIT ? OFFSET ?", (limit, offset),
            ).fetchall()
        return [dict(r) for r in rows]

    def get(self, scan_id: str) -> ScanResult | None:
        with closing(self._connect()) as conn:
            row = conn.execute("SELECT result_json FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
        return ScanResult.model_validate(json.loads(row["result_json"])) if row else None

    def get_source(self, scan_id: str) -> str | None:
        with closing(self._connect()) as conn:
            row = conn.execute("SELECT source_text FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
        return row["source_text"] if row else None

    def count(self) -> int:
        with closing(self._connect()) as conn:
            return conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]

    # --- explanation cache (week 8) ---
    def get_explanation(self, cache_key: str) -> str | None:
        with closing(self._connect()) as conn:
            row = conn.execute("SELECT result_json FROM explanations WHERE cache_key = ?", (cache_key,)).fetchone()
        return row["result_json"] if row else None

    def save_explanation(self, cache_key: str, result_json: str) -> None:
        with closing(self._connect()) as conn, conn:
            conn.execute("INSERT OR REPLACE INTO explanations (cache_key, result_json) VALUES (?, ?)",
                         (cache_key, result_json))

    # --- fix attempts (week 9) ---
    def save_fix_attempt(self, scan_id: str, finding_id: str, status: str, result_json: str) -> None:
        with closing(self._connect()) as conn, conn:
            conn.execute("INSERT INTO fix_attempts (scan_id, finding_id, status, result_json) VALUES (?, ?, ?, ?)",
                         (scan_id, finding_id, status, result_json))

    def list_fix_attempts(self, scan_id: str) -> list[dict]:
        with closing(self._connect()) as conn:
            rows = conn.execute("SELECT finding_id, created_at, status FROM fix_attempts WHERE scan_id = ? "
                                "ORDER BY attempt_id DESC", (scan_id,)).fetchall()
        return [dict(r) for r in rows]
