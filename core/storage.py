"""
LogNorm SQLite storage.

Schema
------
sessions
  session_id   TEXT PRIMARY KEY
  source_type  TEXT NOT NULL
  filename     TEXT
  created_at   TEXT NOT NULL
  total_events INTEGER
  failed_count INTEGER

events
  id           INTEGER PRIMARY KEY AUTOINCREMENT
  event_id     TEXT NOT NULL UNIQUE
  session_id   TEXT NOT NULL
  source_type  TEXT NOT NULL
  created_at   TEXT
  category     TEXT   -- JSON array serialised as string
  event_action TEXT
  severity     INTEGER
  host_name    TEXT
  process_name TEXT
  user_name    TEXT
  src_ip       TEXT
  dst_ip       TEXT
  ecs_json     TEXT NOT NULL
  indexed_at   TEXT NOT NULL

Indexes on (source_type), (host_name), (session_id), (indexed_at DESC).
"""

import json
import logging
import sqlite3
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

_DDL = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS sessions (
    session_id   TEXT PRIMARY KEY,
    source_type  TEXT NOT NULL,
    filename     TEXT,
    created_at   TEXT NOT NULL,
    total_events INTEGER DEFAULT 0,
    failed_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id     TEXT NOT NULL UNIQUE,
    session_id   TEXT NOT NULL,
    source_type  TEXT NOT NULL,
    created_at   TEXT,
    category     TEXT,
    event_action TEXT,
    severity     INTEGER DEFAULT 0,
    host_name    TEXT,
    process_name TEXT,
    user_name    TEXT,
    src_ip       TEXT,
    dst_ip       TEXT,
    ecs_json     TEXT NOT NULL,
    indexed_at   TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

CREATE INDEX IF NOT EXISTS idx_events_source  ON events (source_type);
CREATE INDEX IF NOT EXISTS idx_events_host    ON events (host_name);
CREATE INDEX IF NOT EXISTS idx_events_session ON events (session_id);
CREATE INDEX IF NOT EXISTS idx_events_time    ON events (indexed_at DESC);
"""


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class Storage:
    def __init__(self, db_path: str):
        self._path = db_path
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(_DDL)

    # ── Write ────────────────────────────────────────────────────────────

    def save_session(
        self,
        session_id: str,
        source_type: str,
        filename: str,
        events: list,
        failed: int,
    ) -> None:
        now = _now()
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO sessions "
                "(session_id, source_type, filename, created_at, total_events, failed_count) "
                "VALUES (?,?,?,?,?,?)",
                (session_id, source_type, filename or "", now,
                 len(events), failed),
            )
            for ev in events:
                ev_id   = ev.get("event", {}).get("id", "")
                cat     = json.dumps(ev.get("event", {}).get("category", []))
                action  = ev.get("event", {}).get("action", "")
                sev     = ev.get("event", {}).get("severity", 0)
                host    = ev.get("host", {}).get("name", "")
                proc    = ev.get("process", {}).get("name", "")
                user    = ev.get("user", {}).get("name", "")
                created = ev.get("event", {}).get("created", "")
                src_ip  = ev.get("network", {}).get("source", {}).get("ip", "")
                dst_ip  = ev.get("network", {}).get("destination", {}).get("ip", "")
                conn.execute(
                    "INSERT OR IGNORE INTO events "
                    "(event_id, session_id, source_type, created_at, category, "
                    " event_action, severity, host_name, process_name, user_name, "
                    " src_ip, dst_ip, ecs_json, indexed_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (ev_id, session_id, source_type, created, cat, action, sev,
                     host, proc, user, src_ip, dst_ip,
                     json.dumps(ev, ensure_ascii=False), now),
                )
            conn.commit()

    # ── Read ─────────────────────────────────────────────────────────────

    def list_sessions(self, limit: int = 50) -> list:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM sessions ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def list_events(
        self,
        page: int        = 1,
        per_page: int    = 50,
        source_type: str = "",
        host_name: str   = "",
        search: str      = "",
        session_id: str  = "",
    ) -> dict:
        where_parts = []
        params: list = []

        if source_type:
            where_parts.append("source_type = ?")
            params.append(source_type)
        if host_name:
            where_parts.append("host_name LIKE ?")
            params.append(f"%{host_name}%")
        if session_id:
            where_parts.append("session_id = ?")
            params.append(session_id)
        if search:
            where_parts.append(
                "(event_action LIKE ? OR host_name LIKE ? OR process_name LIKE ? "
                " OR user_name LIKE ? OR src_ip LIKE ? OR dst_ip LIKE ?)"
            )
            like = f"%{search}%"
            params.extend([like, like, like, like, like, like])

        where = ("WHERE " + " AND ".join(where_parts)) if where_parts else ""

        with self._connect() as conn:
            total = conn.execute(
                f"SELECT COUNT(*) FROM events {where}", params
            ).fetchone()[0]

            offset = (page - 1) * per_page
            rows = conn.execute(
                f"SELECT event_id, source_type, created_at, category, event_action, "
                f"       severity, host_name, process_name, user_name, src_ip, dst_ip, "
                f"       session_id, indexed_at "
                f"FROM events {where} "
                f"ORDER BY indexed_at DESC LIMIT ? OFFSET ?",
                params + [per_page, offset],
            ).fetchall()

        return {
            "total":    total,
            "page":     page,
            "per_page": per_page,
            "pages":    max(1, (total + per_page - 1) // per_page),
            "records":  [dict(r) for r in rows],
        }

    def get_event(self, event_id: str) -> Optional[dict]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT ecs_json FROM events WHERE event_id = ?", (event_id,)
            ).fetchone()
        if row:
            return json.loads(row["ecs_json"])
        return None

    def export_events_json(self, session_id: str = "") -> list:
        where  = "WHERE session_id = ?" if session_id else ""
        params = [session_id] if session_id else []
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT ecs_json FROM events {where} ORDER BY indexed_at DESC",
                params,
            ).fetchall()
        return [json.loads(r["ecs_json"]) for r in rows]

    # ── Delete ───────────────────────────────────────────────────────────

    def delete_all(self) -> int:
        with self._connect() as conn:
            count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            conn.execute("DELETE FROM events")
            conn.execute("DELETE FROM sessions")
            conn.commit()
        return count
