"""Small local SQLite store with a one-time legacy JSON import."""
import json
import sqlite3
from pathlib import Path
from typing import Any


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(db_path), timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute(
        """CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            payload TEXT NOT NULL
        )"""
    )
    connection.execute("CREATE INDEX IF NOT EXISTS idx_analyses_created_at ON analyses(id DESC)")
    connection.commit()
    return connection


def load_records(db_path: Path, legacy_path: Path | None = None) -> list[dict[str, Any]]:
    with _connect(db_path) as connection:
        count = connection.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]
        if count == 0 and legacy_path and legacy_path.exists():
            try:
                legacy = json.loads(legacy_path.read_text(encoding="utf-8"))
                if isinstance(legacy, list):
                    connection.executemany(
                        "INSERT INTO analyses(payload) VALUES (?)",
                        [(json.dumps(item, ensure_ascii=False),) for item in legacy[-500:] if isinstance(item, dict)],
                    )
                    connection.commit()
            except (OSError, json.JSONDecodeError):
                # Preserve a broken legacy file for manual recovery; start with an empty DB.
                pass
        rows = connection.execute("SELECT payload FROM analyses ORDER BY id ASC").fetchall()
        result = []
        for row in rows:
            try:
                value = json.loads(row["payload"])
                if isinstance(value, dict):
                    result.append(value)
            except json.JSONDecodeError:
                continue
        return result[-500:]


def save_records(db_path: Path, records: list[dict[str, Any]]) -> None:
    bounded = records[-500:]
    with _connect(db_path) as connection:
        connection.execute("DELETE FROM analyses")
        connection.executemany(
            "INSERT INTO analyses(payload) VALUES (?)",
            [(json.dumps(item, ensure_ascii=False),) for item in bounded],
        )
        connection.commit()


def append_records(db_path: Path, records: list[dict[str, Any]], legacy_path: Path | None = None) -> None:
    if not records:
        return
    existing = load_records(db_path, legacy_path)
    save_records(db_path, existing + records)
