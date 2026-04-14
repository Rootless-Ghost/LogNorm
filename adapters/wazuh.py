"""
Wazuh JSON alerts adapter.

Parses Wazuh alert output in the following formats:
  1. NDJSON — one JSON object per line (wazuh-alerts.json / filebeat format)
  2. JSON array — list of alert objects
  3. Single JSON object
  4. OpenSearch / Elastic _source wrapper  {"_source": {...}}

The Wazuh alert schema normalised here matches the format produced by
Wazuh 4.x on the lab manager at the configured host.  Agent, rule,
and data (win.eventdata / syscheck / audit) blocks are all handled.
"""

import json
import logging
from typing import Optional

from adapters.base import BaseAdapter
from core.models import make_ecs_event, safe_int

logger = logging.getLogger(__name__)

# Wazuh rule level → ECS-lite severity (0–100)
_LEVEL_SEVERITY = {
    0: 0, 1: 5, 2: 10, 3: 15, 4: 20, 5: 25, 6: 30,
    7: 35, 8: 40, 9: 45, 10: 50, 11: 55, 12: 60,
    13: 70, 14: 80, 15: 90,
}

# Windows EventID known inside Wazuh alerts (data.win.system.eventID)
_WEL_OUTCOME = {
    "4624": "success", "4625": "failure", "4634": "success",
    "4648": "success", "4688": "success", "4698": "success",
    "4720": "success", "4726": "success", "4740": "success",
}


def _safe_get(obj: dict, *keys, default=""):
    """Safely traverse nested dict keys."""
    current = obj
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key, default)
        if current is None:
            return default
    return current if current != "" else default


class WazuhAdapter(BaseAdapter):
    source_type = "wazuh"

    def _parse_records(self, raw: str) -> list:
        """
        Accept NDJSON, JSON array, single JSON object, or
        OpenSearch response with _source wrappers.
        """
        raw = raw.strip()
        if not raw:
            return []

        # Strategy 1: JSON array
        if raw.startswith("["):
            try:
                items = json.loads(raw)
                if isinstance(items, list):
                    return [i.get("_source", i) if isinstance(i, dict) else i
                            for i in items]
            except json.JSONDecodeError:
                pass

        # Strategy 2: Single JSON object
        if raw.startswith("{"):
            try:
                obj = json.loads(raw)
                if isinstance(obj, dict):
                    return [obj.get("_source", obj)]
            except json.JSONDecodeError:
                pass

        # Strategy 3: NDJSON (one object per line)
        records = []
        for line in raw.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    records.append(obj.get("_source", obj))
            except json.JSONDecodeError:
                logger.debug("Wazuh NDJSON line parse error: %r", line[:80])
        return records

    def _normalize_record(self, alert: dict) -> Optional[dict]:
        if not isinstance(alert, dict):
            return None

        # ── Core fields ───────────────────────────────────────────────
        timestamp  = _safe_get(alert, "timestamp")
        agent      = alert.get("agent", {})
        rule       = alert.get("rule", {})
        data       = alert.get("data", {})
        location   = _safe_get(alert, "location")

        agent_name = _safe_get(agent, "name")
        agent_ip   = _safe_get(agent, "ip")
        host_ips   = [agent_ip] if agent_ip else []

        rule_id    = str(_safe_get(rule, "id", default=""))
        rule_desc  = _safe_get(rule, "description")
        rule_level = safe_int(_safe_get(rule, "level"), 0)
        severity   = _LEVEL_SEVERITY.get(min(rule_level, 15), rule_level * 5)

        # MITRE tags from rule
        mitre_ids = _safe_get(rule, "mitre", "id") or []
        if isinstance(mitre_ids, str):
            mitre_ids = [mitre_ids]
        tags = list(mitre_ids) if mitre_ids else []
        rule_groups = rule.get("groups", []) or []
        if isinstance(rule_groups, list):
            tags += [g for g in rule_groups if g and g not in tags]

        # ── Windows event data (data.win.*) ──────────────────────────
        win  = data.get("win", {})
        wsys = win.get("system", {})
        wed  = win.get("eventdata", {})

        w_event_id = _safe_get(wsys, "eventID") or _safe_get(wsys, "eventId")
        w_computer = _safe_get(wsys, "computer")
        w_provider = _safe_get(wsys, "providerName")
        w_time     = _safe_get(wsys, "systemTime")

        target_user = _safe_get(wed, "targetUserName") or _safe_get(wed, "subjectUserName")
        subject_user = _safe_get(wed, "subjectUserName")
        ip_addr    = _safe_get(wed, "ipAddress")
        logon_type = _safe_get(wed, "logonType")
        proc_name  = _safe_get(wed, "newProcessName") or _safe_get(wed, "processName")
        proc_id    = safe_int(_safe_get(wed, "newProcessId") or _safe_get(wed, "processId"))
        win_cmd    = _safe_get(wed, "commandLine")

        # Outcome from Windows logon events
        outcome = _WEL_OUTCOME.get(w_event_id, "unknown")

        # Host: prefer agent name, fall back to win computer
        host_name = agent_name or w_computer
        created   = timestamp or w_time

        # ── Category inference ────────────────────────────────────────
        category, etype, action = _infer_category(rule_groups, w_event_id, rule_desc)

        # ── syscheck (file integrity monitoring) ─────────────────────
        syscheck = alert.get("syscheck", {}) or {}
        file_path   = _safe_get(syscheck, "path")
        file_md5    = _safe_get(syscheck, "md5_before") or _safe_get(syscheck, "md5_after")
        file_sha256 = _safe_get(syscheck, "sha256_before") or _safe_get(syscheck, "sha256_after")
        import os as _os
        file_name = _os.path.basename(file_path) if file_path else ""
        file_ext  = file_name.rsplit(".", 1)[-1] if "." in file_name else ""
        sc_event  = _safe_get(syscheck, "event")
        if sc_event:
            category = ["file"]
            etype = {"added": ["creation"], "modified": ["change"],
                     "deleted": ["deletion"]}.get(sc_event.lower(), ["change"])
            action = f"File {sc_event}"

        # ── audit (Linux audit log data) ──────────────────────────────
        audit_data = data.get("audit", {}) or {}
        audit_user = _safe_get(audit_data, "auid") or _safe_get(audit_data, "uid")
        audit_cmd  = _safe_get(audit_data, "command") or _safe_get(audit_data, "execve", "a0")

        user_name = target_user or audit_user
        user_domain = ""
        if user_name and "\\" in user_name:
            user_domain, user_name = user_name.split("\\", 1)

        return make_ecs_event(
            source_type       = "wazuh",
            source_tool       = "wazuh",
            created           = created or None,
            category          = category,
            event_type        = etype,
            action            = action or rule_desc,
            outcome           = outcome,
            severity          = severity,
            original_event_id = rule_id,
            host_name         = host_name,
            host_ip           = host_ips if host_ips else None,
            os_type           = "windows" if w_event_id else "",
            process_pid       = proc_id,
            process_name      = _os.path.basename(proc_name) if proc_name else "",
            process_exe       = proc_name,
            process_cmdline   = win_cmd or audit_cmd,
            src_ip            = ip_addr,
            file_path         = file_path,
            file_name         = file_name,
            file_ext          = file_ext,
            file_md5          = file_md5,
            file_sha256       = file_sha256,
            user_name         = user_name,
            user_domain       = user_domain,
            tags              = tags,
            original_log      = {
                "rule_id": rule_id, "rule_level": rule_level,
                "description": rule_desc, "agent": agent_name,
                "location": location,
            },
        )


def _infer_category(groups: list, event_id: str, description: str) -> tuple:
    """Infer ECS category/type/action from Wazuh rule groups and description."""
    groups_lower = [g.lower() for g in (groups or [])]
    desc_lower   = (description or "").lower()

    # Authentication events
    if any(g in groups_lower for g in ("authentication_success", "authentication_failed",
                                        "win_authentication", "pam")):
        outcome = "success" if "success" in groups_lower else "failure"
        return (["authentication"], ["start"], description or "Authentication event")

    # Windows logon events
    if event_id in ("4624", "4625", "4634", "4647", "4648"):
        return (["authentication"], ["start"], description or f"WEL {event_id}")

    # Process events
    if "process_creation" in groups_lower or event_id in ("4688", "4689"):
        return (["process"], ["start"], description or "Process event")

    # Sysmon events
    if "sysmon" in groups_lower:
        return (["process"], ["info"], description or "Sysmon event")

    # File integrity
    if any(g in groups_lower for g in ("ossec", "syscheck", "file_monitor")):
        return (["file"], ["change"], description or "File change")

    # Network / firewall
    if any(g in groups_lower for g in ("firewall", "network", "ids", "ips")):
        return (["network"], ["info"], description or "Network event")

    # Web / proxy
    if any(g in groups_lower for g in ("web", "proxy", "apache", "nginx", "iis")):
        return (["network"], ["access"], description or "Web event")

    # IAM
    if any(g in groups_lower for g in ("account_changed", "adduser", "windows_security")):
        return (["iam"], ["change"], description or "Account change")

    # Fallback
    return (["process"], ["info"], description or "Wazuh alert")
