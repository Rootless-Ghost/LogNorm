"""
Windows Event Log CSV adapter.

Parses Security.evtx (and other .evtx logs) exported to CSV via:
  Get-WinEvent -LogName Security | Export-Csv security.csv
  wevtutil qe Security /f:text (then converted to CSV)
  EndpointTriage Invoke-EndpointTriage.ps1 Security.csv output

Column detection is flexible — the adapter inspects the header row
and maps whichever standard columns are present.  At minimum it needs
a TimeCreated/TimeGenerated column and an Id/EventID column.

EventID coverage: 4624 4625 4634 4647 4648 4656 4663 4688 4689
                  4698 4699 4700 4701 4702 4719 4720 4722 4723
                  4724 4725 4726 4728 4732 4738 4740 4756 5140 7045
"""

import csv
import io
import logging
from typing import Optional

from adapters.base import BaseAdapter
from core.models import make_ecs_event, safe_int

logger = logging.getLogger(__name__)

# EventID → (category, type, action, severity, outcome)
_WEL_MAP: dict[int, tuple] = {
    4624: (["authentication"], ["start"],               "User logon",                      0,   "success"),
    4625: (["authentication"], ["start"],               "Logon failure",                   30,  "failure"),
    4634: (["authentication"], ["end"],                 "User logoff",                     0,   "success"),
    4647: (["authentication"], ["end"],                 "User-initiated logoff",            0,   "success"),
    4648: (["authentication"], ["start"],               "Logon with explicit credentials", 20,  "success"),
    4656: (["file"],           ["access"],              "Handle to object requested",      5,   "unknown"),
    4663: (["file"],           ["access"],              "Object access attempt",           5,   "unknown"),
    4688: (["process"],        ["start"],               "Process created",                 0,   "success"),
    4689: (["process"],        ["end"],                 "Process exited",                  0,   "success"),
    4698: (["process"],        ["creation"],            "Scheduled task created",          20,  "success"),
    4699: (["process"],        ["deletion"],            "Scheduled task deleted",          20,  "success"),
    4700: (["process"],        ["change"],              "Scheduled task enabled",          15,  "success"),
    4701: (["process"],        ["change"],              "Scheduled task disabled",         15,  "success"),
    4702: (["process"],        ["change"],              "Scheduled task updated",          15,  "success"),
    4719: (["configuration"],  ["change"],              "System audit policy changed",     30,  "success"),
    4720: (["iam"],            ["user", "creation"],    "User account created",            25,  "success"),
    4722: (["iam"],            ["user", "change"],      "User account enabled",            15,  "success"),
    4723: (["iam"],            ["user", "change"],      "Password change attempt",         10,  "unknown"),
    4724: (["iam"],            ["user", "change"],      "Password reset attempt",          20,  "unknown"),
    4725: (["iam"],            ["user", "change"],      "User account disabled",           15,  "success"),
    4726: (["iam"],            ["user", "deletion"],    "User account deleted",            25,  "success"),
    4728: (["iam"],            ["group", "change"],     "Member added to global group",    20,  "success"),
    4732: (["iam"],            ["group", "change"],     "Member added to local group",     20,  "success"),
    4738: (["iam"],            ["user", "change"],      "User account changed",            15,  "success"),
    4740: (["iam"],            ["user", "change"],      "User account locked out",         40,  "success"),
    4756: (["iam"],            ["group", "change"],     "Member added to universal group", 20,  "success"),
    5140: (["network"],        ["access"],              "Network share object accessed",   10,  "success"),
    7045: (["process"],        ["creation"],            "New service installed",           30,  "success"),
}

# Logon type integer → name
_LOGON_TYPES = {
    "2": "interactive", "3": "network",      "4": "batch",
    "5": "service",     "7": "unlock",       "8": "networkcleartext",
    "9": "newcredentials", "10": "remoteinteractive",
    "11": "cachedinteractive",
}

# Column name aliases — maps normalized lowercase key to known column names
_COL_ALIASES = {
    "timecreated": ["TimeCreated", "TimeGenerated", "Time Created", "Date and Time",
                    "time_created", "time_generated"],
    "eventid":     ["Id", "EventID", "Event ID", "EventId", "id", "event_id"],
    "computername":["MachineName", "ComputerName", "Computer", "machine_name",
                    "computer_name", "Hostname"],
    "message":     ["Message", "message", "Description"],
    "userid":      ["UserId", "UserID", "user_id", "SID"],
    "provider":    ["ProviderName", "Provider", "provider_name"],
    "level":       ["LevelDisplayName", "Level", "level"],
    "targetuser":  ["TargetUserName", "TargetUser", "target_user_name"],
    "subjectuser": ["SubjectUserName", "SubjectUser", "subject_user_name"],
    "ipaddress":   ["IpAddress", "IPAddress", "ip_address", "SourceIpAddress"],
    "logontype":   ["LogonType", "logon_type"],
    "process":     ["NewProcessName", "ProcessName", "process_name", "NewProcess"],
    "processid":   ["NewProcessId", "ProcessId", "process_id", "pid"],
    "parentproc":  ["ParentProcessName", "ParentImage", "parent_process_name"],
    "cmdline":     ["CommandLine", "ProcessCommandLine", "command_line"],
}


def _build_col_map(headers: list) -> dict:
    """Return a dict mapping canonical key → actual CSV column name."""
    header_set = {h.strip(): h.strip() for h in headers}
    result = {}
    for canonical, aliases in _COL_ALIASES.items():
        for alias in aliases:
            if alias in header_set:
                result[canonical] = alias
                break
    return result


class WELAdapter(BaseAdapter):
    source_type = "wel"

    def _parse_records(self, raw: str) -> list:
        """Parse CSV text into list of row dicts."""
        raw = raw.strip()
        if not raw:
            return []
        reader = csv.DictReader(io.StringIO(raw))
        try:
            rows = list(reader)
        except Exception as exc:
            logger.warning("WEL CSV parse error: %s", exc)
            return []
        return rows

    def _normalize_record(self, row: dict) -> Optional[dict]:
        headers = list(row.keys())
        col = _build_col_map(headers)

        def get(canonical, default=""):
            col_name = col.get(canonical)
            if col_name:
                return (row.get(col_name) or "").strip()
            # Fallback: try the canonical name directly
            return (row.get(canonical) or "").strip()

        event_id_raw = get("eventid")
        event_id_int = safe_int(event_id_raw, 0)
        if event_id_int == 0:
            return None

        time_str   = get("timecreated")
        computer   = get("computername")
        message    = get("message")
        target_user = get("targetuser")
        subject_user = get("subjectuser")
        ip_addr    = get("ipaddress")
        logon_type = get("logontype")
        proc_path  = get("process")
        proc_id    = safe_int(get("processid"))
        parent_proc= get("parentproc")
        cmdline    = get("cmdline")

        meta = _WEL_MAP.get(event_id_int)
        if meta:
            category, etype, action, severity, outcome = meta
        else:
            category, etype, action, severity, outcome = (
                ["process"], ["info"],
                f"WEL event {event_id_int}", 0, "unknown"
            )

        import os as _os
        proc_name = _os.path.basename(proc_path) if proc_path else ""
        parent_name = _os.path.basename(parent_proc) if parent_proc else ""

        # Logon type description for action enrichment
        if event_id_int in (4624, 4625) and logon_type:
            lt_name = _LOGON_TYPES.get(logon_type, f"type-{logon_type}")
            action = f"{action} ({lt_name})"

        # Determine user fields: prefer target_user, fall back to subject_user
        user_name = target_user or subject_user
        user_domain = ""
        if "\\" in user_name:
            user_domain, user_name = user_name.split("\\", 1)

        tags = []

        return make_ecs_event(
            source_type       = "wel",
            source_tool       = "windows-event-log",
            created           = time_str or None,
            category          = category,
            event_type        = etype,
            action            = action,
            outcome           = outcome,
            severity          = severity,
            original_event_id = str(event_id_int),
            host_name         = computer,
            os_type           = "windows",
            process_pid       = proc_id,
            process_name      = proc_name,
            process_exe       = proc_path,
            process_cmdline   = cmdline,
            parent_name       = parent_name,
            parent_exe        = parent_proc,
            src_ip            = ip_addr if event_id_int not in (4688, 4689) else "",
            dst_ip            = "",
            user_name         = user_name,
            user_domain       = user_domain,
            tags              = tags,
            original_log      = {
                "EventID": event_id_raw,
                "TimeCreated": time_str,
                "Computer": computer,
                "Message": message[:256] if message else "",
            },
        )
