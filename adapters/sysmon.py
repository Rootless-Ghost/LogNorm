"""
Sysmon XML adapter.

Parses Microsoft Sysinternals Sysmon event logs exported as XML.

Supported input formats:
  1. Full XML document with <Events> root element (wevtutil export)
  2. Stream of bare <Event> fragments (one per line or concatenated)
  3. Single <Event> element

EventID → ECS-lite mapping covers EventIDs 1–29.
"""

import logging
import os
import re
import xml.etree.ElementTree as ET
from typing import Optional

from adapters.base import BaseAdapter
from core.models import make_ecs_event, parse_hash_string, safe_int

logger = logging.getLogger(__name__)

# XML namespace used in Sysmon event logs
_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
_NS_MAP = {"e": _NS}

# EventID → (category, type, action, severity_bump)
_EVENT_MAP: dict[int, tuple] = {
    1:  (["process"],       ["start"],               "Process created",                   0),
    2:  (["file"],          ["change"],              "File creation time changed",         10),
    3:  (["network"],       ["start"],               "Network connection",                 0),
    4:  (["process"],       ["change"],              "Sysmon service state changed",       0),
    5:  (["process"],       ["end"],                 "Process terminated",                 0),
    6:  (["driver"],        ["start"],               "Driver loaded",                      20),
    7:  (["library"],       ["start"],               "Image loaded",                       5),
    8:  (["process"],       ["change"],              "CreateRemoteThread detected",        50),
    9:  (["file"],          ["access"],              "RawAccessRead",                      30),
    10: (["process"],       ["access"],              "Process accessed",                   20),
    11: (["file"],          ["creation"],            "File created",                       0),
    12: (["registry"],      ["creation", "deletion"],"Registry object created/deleted",    5),
    13: (["registry"],      ["change"],              "Registry value set",                 5),
    14: (["registry"],      ["change"],              "Registry object renamed",            5),
    15: (["file"],          ["creation"],            "File stream created",                10),
    16: (["configuration"], ["change"],              "Sysmon configuration changed",       0),
    17: (["file"],          ["creation"],            "Pipe created",                       10),
    18: (["file"],          ["access"],              "Pipe connected",                     10),
    19: (["process"],       ["creation"],            "WMI filter registered",              30),
    20: (["process"],       ["creation"],            "WMI consumer registered",            30),
    21: (["process"],       ["change"],              "WMI consumer-to-filter bound",       30),
    22: (["network"],       ["protocol"],            "DNS query",                          0),
    23: (["file"],          ["deletion"],            "File deleted",                       10),
    24: (["file"],          ["access"],              "Clipboard changed",                  5),
    25: (["process"],       ["change"],              "Process tampering detected",         40),
    26: (["file"],          ["deletion"],            "File delete logged",                 10),
    27: (["file"],          ["change"],              "File block executable",              20),
    28: (["file"],          ["change"],              "File block shredding",               20),
    29: (["file"],          ["creation"],            "File executable detected",           15),
}

# Tags applied to high-interest EventIDs
_MITRE_HINTS: dict[int, list] = {
    8:  ["T1055"],   # CreateRemoteThread → process injection
    9:  ["T1006"],   # RawAccessRead → direct volume access
    10: ["T1055"],   # ProcessAccess → process injection
    19: ["T1047"],   # WMI filter
    20: ["T1047"],   # WMI consumer
    21: ["T1047"],   # WMI binding
    25: ["T1055"],   # Process tampering
}


def _tag(name: str) -> str:
    return f"{{{_NS}}}{name}"


def _get_data(event_data, name: str) -> str:
    """Return text of <Data Name='name'> element, or empty string."""
    for child in event_data:
        if child.get("Name") == name:
            return (child.text or "").strip()
    return ""


class SysmonAdapter(BaseAdapter):
    source_type = "sysmon"

    def _parse_records(self, raw: str) -> list:
        """
        Extract all <Event> elements from the raw XML string.
        Handles full documents (<Events> root) and bare fragments.
        """
        raw = raw.strip()
        if not raw:
            return []

        # Strip XML declaration if present — it confuses fragment parsing
        raw_body = re.sub(r"<\?xml[^?]*\?>", "", raw, count=1).strip()

        # Strategy 1: try as a full XML document
        try:
            root = ET.fromstring(raw_body)
            tag = root.tag.lower()
            if "events" in tag:
                return list(root)
            if "event" in tag:
                return [root]
        except ET.ParseError:
            pass

        # Strategy 2: extract individual <Event>...</Event> fragments
        pattern = re.compile(
            r"<Event(?:\s[^>]*)?>.*?</Event>",
            re.DOTALL | re.IGNORECASE
        )
        fragments = pattern.findall(raw_body)
        elements = []
        for frag in fragments:
            try:
                elements.append(ET.fromstring(frag))
            except ET.ParseError as exc:
                logger.debug("Sysmon fragment parse error: %s", exc)
        return elements

    def _normalize_record(self, elem) -> Optional[dict]:
        """Map one <Event> ElementTree element to an ECS-lite dict."""
        # ── System block ──────────────────────────────────────────────
        system = elem.find(_tag("System"))
        if system is None:
            # Try without namespace
            system = elem.find("System")
        if system is None:
            return None

        def sys_text(name):
            child = system.find(_tag(name))
            if child is None:
                child = system.find(name)
            if child is not None:
                return (child.text or "").strip()
            return ""

        event_id_raw = sys_text("EventID")
        event_id_int = safe_int(event_id_raw, 0)
        time_str = ""
        tc = system.find(_tag("TimeCreated"))
        if tc is None:
            tc = system.find("TimeCreated")
        if tc is not None:
            time_str = tc.get("SystemTime", "")
        computer = sys_text("Computer")

        # ── EventData block ───────────────────────────────────────────
        ed = elem.find(_tag("EventData"))
        if ed is None:
            ed = elem.find("EventData")
        if ed is None:
            ed = []

        def d(name):
            return _get_data(ed, name)

        # ── ECS mapping from EventID ──────────────────────────────────
        meta = _EVENT_MAP.get(event_id_int, (["process"], ["info"], f"Sysmon event {event_id_int}", 0))
        category, etype, action, sev_bump = meta

        # ── Extract RuleName MITRE tag ────────────────────────────────
        rule_name = d("RuleName")
        tags = []
        if rule_name:
            # SwiftOnSecurity format: "technique_id=T1059.001,technique_name=..."
            for part in rule_name.split(","):
                if "technique_id=" in part.lower():
                    tid = part.split("=", 1)[-1].strip()
                    if tid:
                        tags.append(tid)

        tags += _MITRE_HINTS.get(event_id_int, [])

        # ── Hashes ────────────────────────────────────────────────────
        hash_str = d("Hashes")
        proc_md5, proc_sha256 = parse_hash_string(hash_str) if hash_str else ("", "")

        # ── User ──────────────────────────────────────────────────────
        user_raw = d("User")
        user_domain, user_name = "", user_raw
        if "\\" in user_raw:
            user_domain, user_name = user_raw.split("\\", 1)

        # ── File fields (EventID 11, 2, 23, 26, 15) ──────────────────
        target_filename = d("TargetFilename") or d("TargetFileName")
        file_name = os.path.basename(target_filename) if target_filename else ""
        file_ext = ""
        if file_name and "." in file_name:
            file_ext = file_name.rsplit(".", 1)[-1]

        # ── Registry fields (EventID 12, 13, 14) ─────────────────────
        reg_target = d("TargetObject")
        reg_details = d("Details")

        # ── Network fields (EventID 3) ────────────────────────────────
        dst_ip   = d("DestinationIp")
        dst_port = safe_int(d("DestinationPort"))
        dst_host = d("DestinationHostname")
        src_ip   = d("SourceIp")
        src_port = safe_int(d("SourcePort"))
        protocol = d("Protocol").lower()
        net_dir  = "egress" if d("Initiated").lower() == "true" else ""

        # ── DNS fields (EventID 22) ───────────────────────────────────
        dns_query = d("QueryName")
        if event_id_int == 22 and dns_query:
            dst_host = dns_query

        # ── Severity ──────────────────────────────────────────────────
        severity = min(100, sev_bump)

        return make_ecs_event(
            source_type   = "sysmon",
            source_tool   = "sysmon",
            event_id      = None,
            created       = time_str or None,
            category      = category,
            event_type    = etype,
            action        = action,
            severity      = severity,
            original_event_id = str(event_id_int),
            host_name     = computer,
            os_type       = "windows",
            process_pid   = safe_int(d("ProcessId")),
            process_ppid  = safe_int(d("ParentProcessId")),
            process_name  = os.path.basename(d("Image")) if d("Image") else "",
            process_exe   = d("Image"),
            process_cmdline = d("CommandLine"),
            process_md5   = proc_md5,
            process_sha256= proc_sha256,
            parent_pid    = safe_int(d("ParentProcessId")),
            parent_name   = os.path.basename(d("ParentImage")) if d("ParentImage") else "",
            parent_exe    = d("ParentImage"),
            parent_cmdline= d("ParentCommandLine"),
            net_direction = net_dir,
            net_transport = protocol,
            dst_ip        = dst_ip,
            dst_port      = dst_port,
            dst_domain    = dst_host,
            src_ip        = src_ip,
            src_port      = src_port,
            file_path     = target_filename,
            file_name     = file_name,
            file_ext      = file_ext,
            reg_path      = reg_target,
            reg_value_data= reg_details,
            user_name     = user_name,
            user_domain   = user_domain,
            tags          = tags if tags else [],
            original_log  = {"EventID": event_id_raw, "RuleName": rule_name,
                             "Computer": computer, "TimeCreated": time_str},
        )
