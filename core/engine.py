"""
LogNorm normalization engine.

NormalizationEngine is the single entry point for all normalization
operations.  It dispatches raw input to the correct adapter, optionally
saves results to the DB, and falls back to disk when the DB is unavailable.
"""

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Optional

from adapters import get_adapter, SUPPORTED_SOURCES
from core.storage import Storage

logger = logging.getLogger(__name__)


class NormalizationEngine:
    def __init__(self, config: dict):
        self._config    = config
        self._storage   = Storage(config.get("db_path", "./lognorm.db"))
        self._output_dir = os.path.abspath(config.get("output_dir", "./output"))
        self._auto_save  = config.get("normalization", {}).get("auto_save", True)
        self._orig_max   = config.get("normalization", {}).get("original_log_max_chars", 4096)

    # ── Public API ──────────────────────────────────────────────────────

    def normalize_text(
        self,
        raw: str,
        source_type: str,
        filename: str = "",
        save: bool = True,
    ) -> dict:
        """
        Normalize raw text from a single source.

        Returns:
            {
              "success":    bool,
              "events":     list of ECS-lite event dicts,
              "failed":     int,
              "total":      int,
              "session_id": str,
              "source_type": str,
            }
        """
        adapter = get_adapter(source_type)
        if adapter is None:
            return {
                "success": False,
                "error": f"Unknown source type: {source_type!r}. "
                         f"Supported: {', '.join(SUPPORTED_SOURCES)}",
                "events": [], "failed": 0, "total": 0, "session_id": "",
            }

        session_id = str(uuid.uuid4())
        events, failed = adapter.parse(raw)

        # Truncate original_log if configured
        if self._orig_max > 0:
            for ev in events:
                log = ev.get("log", {})
                orig = log.get("original_log", {})
                if isinstance(orig, dict):
                    for k, v in orig.items():
                        if isinstance(v, str) and len(v) > self._orig_max:
                            orig[k] = v[:self._orig_max] + "…"

        should_save = save and self._auto_save
        if should_save and events:
            try:
                self._storage.save_session(
                    session_id  = session_id,
                    source_type = source_type,
                    filename    = filename,
                    events      = events,
                    failed      = failed,
                )
            except Exception as exc:
                logger.warning("DB save failed — falling back to disk: %s", exc)
                self._fallback_to_disk(session_id, source_type, events, failed)

        return {
            "success":    True,
            "events":     events,
            "failed":     failed,
            "total":      len(events) + failed,
            "session_id": session_id,
            "source_type": source_type,
        }

    def get_sources(self) -> list:
        return SUPPORTED_SOURCES

    def get_sessions(self, limit: int = 50) -> list:
        return self._storage.list_sessions(limit)

    def get_records(
        self,
        page: int        = 1,
        per_page: int    = 50,
        source_type: str = "",
        host_name: str   = "",
        search: str      = "",
        session_id: str  = "",
    ) -> dict:
        return self._storage.list_events(
            page=page, per_page=per_page,
            source_type=source_type, host_name=host_name,
            search=search, session_id=session_id,
        )

    def get_record(self, event_id: str) -> Optional[dict]:
        return self._storage.get_event(event_id)

    def export_json(self, session_id: str = "") -> list:
        return self._storage.export_events_json(session_id)

    def export_csv_rows(self, session_id: str = "") -> tuple[list, list]:
        """Return (headers, rows) for CSV export."""
        events = self._storage.export_events_json(session_id)
        headers = [
            "event_id", "created", "source_type", "category", "action",
            "outcome", "severity", "host_name", "user_name",
            "process_name", "process_cmdline", "src_ip", "dst_ip", "dst_port",
            "tags",
        ]
        rows = []
        for ev in events:
            e   = ev.get("event", {})
            h   = ev.get("host", {})
            p   = ev.get("process", {})
            net = ev.get("network", {})
            u   = ev.get("user", {})
            rows.append([
                e.get("id", ""),
                e.get("created", ""),
                e.get("source_type", ""),
                "|".join(e.get("category", [])),
                e.get("action", ""),
                e.get("outcome", ""),
                e.get("severity", 0),
                h.get("name", ""),
                u.get("name", ""),
                p.get("name", ""),
                p.get("command_line", ""),
                net.get("source", {}).get("ip", ""),
                net.get("destination", {}).get("ip", ""),
                net.get("destination", {}).get("port", ""),
                "|".join(ev.get("tags", [])),
            ])
        return headers, rows

    def clear_all(self) -> int:
        return self._storage.delete_all()

    # ── Fallback ────────────────────────────────────────────────────────

    def _fallback_to_disk(self, session_id: str, source_type: str,
                           events: list, failed: int) -> None:
        os.makedirs(self._output_dir, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        fname = f"fallback_{source_type}_{ts}_{session_id[:8]}.json"
        path  = os.path.join(self._output_dir, fname)
        payload = {
            "session_id": session_id,
            "source_type": source_type,
            "saved_at": ts,
            "events": events,
            "failed": failed,
        }
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2)
            logger.info("Fallback written: %s", path)
        except OSError as exc:
            logger.error("Could not write fallback file: %s", exc)
