"""
Linux auth.log / syslog adapter.

Parses standard Linux authentication and system log formats:
  - /var/log/auth.log  (Debian/Ubuntu)
  - /var/log/secure    (RHEL/CentOS)
  - /var/log/syslog    (general)
  - journald text export (systemd-journald)

Supports:
  RFC 3164: "MMM DD HH:MM:SS hostname process[pid]: message"
  RFC 5424: "<priority>version ISO-timestamp hostname app proc-id msg-id msg"
  journald: "YYYY-MM-DD HH:MM:SS hostname process[pid]: message"

Detects and classifies:
  SSH:    Accepted/Failed password, publickey, Invalid user, Disconnected
  sudo:   TTY/PWD/USER/COMMAND fields
  PAM:    session opened/closed, authentication failure
  cron:   CMD entries
  useradd / userdel / usermod: account changes
  su:     switch user events
  systemd: service start/stop
"""

import logging
import re
from datetime import datetime
from typing import Optional

from adapters.base import BaseAdapter
from core.models import make_ecs_event

logger = logging.getLogger(__name__)

# ── RFC 3164 ────────────────────────────────────────────────────────────
_RFC3164 = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<process>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.+)$"
)

# ── RFC 5424 ─────────────────────────────────────────────────────────────
_RFC5424 = re.compile(
    r"^<\d+>\d\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<process>\S+)\s+"
    r"(?P<pid>\S+)\s+\S+\s+(?:\[.*?\]\s*)?(?P<msg>.+)$"
)

# ── journald ─────────────────────────────────────────────────────────────
_JOURNALD = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T?\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)\s+"
    r"(?P<host>\S+)\s+(?P<process>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.+)$"
)

# ── Message classifiers ───────────────────────────────────────────────────
# Each entry: (pattern, category, type, action, severity, outcome, field_extractor)
_SSH_ACCEPTED = re.compile(
    r"Accepted (?P<method>\w+) for (?P<user>\S+) from (?P<ip>[\d.:]+) port (?P<port>\d+)"
)
_SSH_FAILED = re.compile(
    r"Failed (?P<method>\w+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.:]+) port (?P<port>\d+)"
)
_SSH_INVALID = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>[\d.:]+)"
)
_SSH_DISC = re.compile(
    r"Disconnected from (?:authenticating |invalid )?user (?P<user>\S+) (?P<ip>[\d.:]+) port (?P<port>\d+)"
)
_SUDO = re.compile(
    r"(?P<user>\S+)\s*:\s*TTY=(?P<tty>\S+)\s*;\s*PWD=(?P<pwd>\S+)\s*;\s*USER=(?P<runas>\S+)\s*;\s*COMMAND=(?P<cmd>.+)$"
)
_PAM_OPEN = re.compile(
    r"pam_unix\((?P<service>[^:]+):session\): session opened for user (?P<user>\S+)"
)
_PAM_FAIL = re.compile(
    r"pam_unix\((?P<service>[^:]+):auth\): authentication failure.*?user=(?P<user>\S+)"
)
_USERADD = re.compile(r"new user: name=(?P<user>\S+)")
_USERDEL = re.compile(r"delete user '(?P<user>[^']+)'")
_SU = re.compile(r"Successful su for (?P<user>\S+) by (?P<by>\S+)")
_SU_FAIL = re.compile(r"FAILED su for (?P<user>\S+) by (?P<by>\S+)")
_CRON = re.compile(r"\((?P<user>[^)]+)\) CMD \((?P<cmd>.+)\)")
_SYSTEMD = re.compile(r"(?P<action>Started|Stopped|Starting|Stopping|Failed) (?P<unit>.+)\.")


def _classify(process: str, msg: str) -> tuple:
    """
    Returns (category, etype, action, severity, outcome, user, src_ip,
             src_port, cmdline, tags).
    """
    proc_lower = process.lower()

    # ── SSH ───────────────────────────────────────────────────────────
    if "sshd" in proc_lower:
        m = _SSH_ACCEPTED.search(msg)
        if m:
            return (
                ["authentication"], ["start"], f"SSH accepted ({m.group('method')})",
                0, "success", m.group("user"), m.group("ip"),
                int(m.group("port")), "", ["T1021.004"],
            )
        m = _SSH_FAILED.search(msg)
        if m:
            return (
                ["authentication"], ["start"], f"SSH failed ({m.group('method')})",
                30, "failure", m.group("user"), m.group("ip"),
                int(m.group("port")), "", ["T1110"],
            )
        m = _SSH_INVALID.search(msg)
        if m:
            return (
                ["authentication"], ["start"], "SSH invalid user",
                35, "failure", m.group("user"), m.group("ip"), None, "", ["T1110"],
            )
        m = _SSH_DISC.search(msg)
        if m:
            return (
                ["authentication"], ["end"], "SSH disconnected",
                0, "unknown", m.group("user"), m.group("ip"),
                int(m.group("port")) if m.group("port") else None, "", [],
            )
        return (["network"], ["info"], f"sshd: {msg[:80]}", 0, "unknown", "", "", None, "", [])

    # ── sudo ──────────────────────────────────────────────────────────
    if "sudo" in proc_lower:
        m = _SUDO.search(msg)
        if m:
            return (
                ["process"], ["start"], f"sudo: {m.group('user')} ran as {m.group('runas')}",
                20, "success", m.group("user"), "", None, m.group("cmd"), ["T1548.003"],
            )
        return (["process"], ["info"], f"sudo: {msg[:80]}", 10, "unknown", "", "", None, "", [])

    # ── PAM ───────────────────────────────────────────────────────────
    if "pam" in proc_lower or msg.startswith("pam_"):
        m = _PAM_OPEN.search(msg)
        if m:
            return (
                ["authentication"], ["start"], f"PAM session opened ({m.group('service')})",
                0, "success", m.group("user"), "", None, "", [],
            )
        m = _PAM_FAIL.search(msg)
        if m:
            return (
                ["authentication"], ["start"], "PAM authentication failure",
                30, "failure", m.group("user"), "", None, "", ["T1078"],
            )
        return (["authentication"], ["info"], f"PAM: {msg[:80]}", 0, "unknown", "", "", None, "", [])

    # ── useradd / userdel / usermod ───────────────────────────────────
    if proc_lower in ("useradd", "userdel", "usermod", "adduser"):
        m = _USERADD.search(msg)
        user = m.group("user") if m else ""
        m2 = _USERDEL.search(msg)
        if m2:
            user = m2.group("user")
        etype = ["deletion"] if "del" in proc_lower else ["creation"]
        return (
            ["iam"], etype, f"{process}: {msg[:80]}",
            25, "success", user, "", None, "", ["T1136"],
        )

    # ── su ────────────────────────────────────────────────────────────
    if proc_lower == "su":
        m = _SU.search(msg)
        if m:
            return (
                ["authentication"], ["start"], f"su to {m.group('user')} by {m.group('by')}",
                20, "success", m.group("user"), "", None, "", ["T1548"],
            )
        m = _SU_FAIL.search(msg)
        if m:
            return (
                ["authentication"], ["start"], f"Failed su to {m.group('user')}",
                35, "failure", m.group("user"), "", None, "", ["T1548"],
            )

    # ── cron ──────────────────────────────────────────────────────────
    if "cron" in proc_lower:
        m = _CRON.search(msg)
        if m:
            return (
                ["process"], ["start"], f"cron: {m.group('user')}",
                0, "success", m.group("user"), "", None, m.group("cmd"), [],
            )

    # ── systemd ───────────────────────────────────────────────────────
    if "systemd" in proc_lower:
        m = _SYSTEMD.search(msg)
        if m:
            act = m.group("action")
            sev = 10 if act == "Failed" else 0
            return (
                ["process"], ["info"], f"systemd: {act} {m.group('unit')}",
                sev, "success" if act != "Failed" else "failure",
                "", "", None, "", [],
            )

    # ── Fallback ──────────────────────────────────────────────────────
    return (["process"], ["info"], f"{process}: {msg[:100]}", 0, "unknown", "", "", None, "", [])


def _parse_line(line: str) -> Optional[dict]:
    """Parse one syslog line and return a raw record dict, or None."""
    for pattern in (_JOURNALD, _RFC5424, _RFC3164):
        m = pattern.match(line)
        if m:
            d = m.groupdict()
            # Normalize timestamp
            ts = d.get("ts") or ""
            if not ts:
                month = d.get("month", "Jan")
                day   = d.get("day", "1").zfill(2)
                time_ = d.get("time", "00:00:00")
                current_year = datetime.utcnow().year
                ts = f"{current_year} {month} {day} {time_}"
            return {
                "timestamp": ts,
                "host":      d.get("host", ""),
                "process":   d.get("process", ""),
                "pid":       d.get("pid", ""),
                "msg":       d.get("msg", ""),
            }
    return None


class SyslogAdapter(BaseAdapter):
    source_type = "syslog"

    def _parse_records(self, raw: str) -> list:
        records = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            rec = _parse_line(line)
            if rec:
                records.append(rec)
            else:
                logger.debug("Syslog line not matched: %r", line[:80])
        return records

    def _normalize_record(self, rec: dict) -> Optional[dict]:
        process   = rec.get("process", "")
        msg       = rec.get("msg", "")
        host_name = rec.get("host", "")
        timestamp = rec.get("timestamp", "")
        pid_str   = rec.get("pid", "")
        pid       = int(pid_str) if pid_str and pid_str.isdigit() else None

        (category, etype, action, severity, outcome,
         user, src_ip, src_port, cmdline, tags) = _classify(process, msg)

        return make_ecs_event(
            source_type       = "syslog",
            source_tool       = "syslog",
            created           = timestamp or None,
            category          = category,
            event_type        = etype,
            action            = action,
            outcome           = outcome,
            severity          = severity,
            host_name         = host_name,
            os_type           = "linux",
            process_pid       = pid,
            process_name      = process,
            process_cmdline   = cmdline,
            src_ip            = src_ip,
            src_port          = src_port,
            user_name         = user,
            tags              = tags,
            original_log      = {
                "process": process, "pid": pid_str,
                "host": host_name, "msg": msg[:512],
            },
        )
