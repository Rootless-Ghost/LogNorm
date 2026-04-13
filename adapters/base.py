"""
LogNorm base adapter.

All source adapters inherit from BaseAdapter.  Subclasses implement
parse_records(raw) which returns a list of raw record dicts, and
normalize_record(record) which maps one raw record to an ECS-lite
event dict via make_ecs_event().

The public interface for callers is:
    adapter.parse(raw_text)          → list of ECS-lite event dicts
    adapter.parse_file(path)         → same, reads from file
    adapter.source_type              → string key for this adapter
"""

import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)


class BaseAdapter:
    """Abstract base class for log source adapters."""

    source_type: str = "unknown"

    # ── Public interface ────────────────────────────────────────────────

    def parse(self, raw: str) -> tuple[list, int]:
        """
        Parse raw text input and return (events, failed_count).

        events      — list of ECS-lite event dicts
        failed_count — number of records that could not be normalized
        """
        records = self._parse_records(raw)
        events = []
        failed = 0
        for rec in records:
            try:
                event = self._normalize_record(rec)
                if event:
                    events.append(event)
                else:
                    failed += 1
            except Exception as exc:
                logger.debug("[%s] normalize_record failed: %s", self.source_type, exc)
                failed += 1
        return events, failed

    def parse_file(self, path: str) -> tuple[list, int]:
        """Read file at path and call parse()."""
        if not os.path.exists(path):
            raise FileNotFoundError(f"File not found: {path}")
        with open(path, encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
        return self.parse(raw)

    # ── Subclass interface ──────────────────────────────────────────────

    def _parse_records(self, raw: str) -> list:
        """
        Split raw input into individual records.
        Returns a list of objects (dicts, strings, or ElementTree Elements
        depending on the adapter).  Subclasses must implement this.
        """
        raise NotImplementedError

    def _normalize_record(self, record) -> Optional[dict]:
        """
        Map a single raw record to an ECS-lite event dict.
        Return None to skip the record (counts as failed).
        Subclasses must implement this.
        """
        raise NotImplementedError
