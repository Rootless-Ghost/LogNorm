"""
LogNorm PostgreSQL storage.

Schema is managed externally via init-db/. Tables expected:
  lognorm_sessions, lognorm_events
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

import psycopg2
import psycopg2.extras

logger = logging.getLogger(__name__)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class Storage:
    def __init__(self, db_path: str):
        self._url = os.environ.get("DATABASE_URL") or db_path

    def _connect(self):
        return psycopg2.connect(self._url)

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
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO lognorm_sessions "
                    "(session_id, source_type, filename, created_at, total_events, failed_count) "
                    "VALUES (%s,%s,%s,%s,%s,%s) "
                    "ON CONFLICT (session_id) DO UPDATE SET "
                    "  total_events = EXCLUDED.total_events, "
                    "  failed_count = EXCLUDED.failed_count",
                    (session_id, source_type, filename or "", now, len(events), failed),
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
                    cur.execute(
                        "INSERT INTO lognorm_events "
                        "(event_id, session_id, source_type, created_at, category, "
                        " event_action, severity, host_name, process_name, user_name, "
                        " src_ip, dst_ip, ecs_json, indexed_at) "
                        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
                        "ON CONFLICT (event_id) DO NOTHING",
                        (ev_id, session_id, source_type, created, cat, action, sev,
                         host, proc, user, src_ip, dst_ip,
                         json.dumps(ev, ensure_ascii=False), now),
                    )
            conn.commit()

    # ── Read ─────────────────────────────────────────────────────────────

    def list_sessions(self, limit: int = 50) -> list:
        with self._connect() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM lognorm_sessions ORDER BY created_at DESC LIMIT %s",
                    (limit,),
                )
                return [dict(r) for r in cur.fetchall()]

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
            where_parts.append("source_type = %s")
            params.append(source_type)
        if host_name:
            where_parts.append("host_name LIKE %s")
            params.append(f"%{host_name}%")
        if session_id:
            where_parts.append("session_id = %s")
            params.append(session_id)
        if search:
            where_parts.append(
                "(event_action LIKE %s OR host_name LIKE %s OR process_name LIKE %s "
                " OR user_name LIKE %s OR src_ip LIKE %s OR dst_ip LIKE %s)"
            )
            like = f"%{search}%"
            params.extend([like, like, like, like, like, like])

        where = ("WHERE " + " AND ".join(where_parts)) if where_parts else ""

        with self._connect() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(f"SELECT COUNT(*) FROM lognorm_events {where}", params)
                total = cur.fetchone()["count"]

                offset = (page - 1) * per_page
                cur.execute(
                    f"SELECT event_id, source_type, created_at, category, event_action, "
                    f"       severity, host_name, process_name, user_name, src_ip, dst_ip, "
                    f"       session_id, indexed_at "
                    f"FROM lognorm_events {where} "
                    f"ORDER BY indexed_at DESC LIMIT %s OFFSET %s",
                    params + [per_page, offset],
                )
                rows = [dict(r) for r in cur.fetchall()]

        return {
            "total":    total,
            "page":     page,
            "per_page": per_page,
            "pages":    max(1, (total + per_page - 1) // per_page),
            "records":  rows,
        }

    def get_event(self, event_id: str) -> Optional[dict]:
        with self._connect() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT ecs_json FROM lognorm_events WHERE event_id = %s",
                    (event_id,),
                )
                row = cur.fetchone()
        if row:
            return json.loads(row["ecs_json"])
        return None

    def export_events_json(self, session_id: str = "") -> list:
        where  = "WHERE session_id = %s" if session_id else ""
        params = [session_id] if session_id else []
        with self._connect() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    f"SELECT ecs_json FROM lognorm_events {where} ORDER BY indexed_at DESC",
                    params,
                )
                return [json.loads(r["ecs_json"]) for r in cur.fetchall()]

    # ── Delete ───────────────────────────────────────────────────────────

    def delete_all(self) -> int:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM lognorm_events")
                count = cur.fetchone()[0]
                cur.execute("DELETE FROM lognorm_events")
                cur.execute("DELETE FROM lognorm_sessions")
            conn.commit()
        return count
