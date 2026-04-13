"""
LogNorm ECS-lite schema reference.

This module provides the canonical field reference table used by the
/schema UI page and the README schema section.  It does not perform
validation — it documents what each field means.
"""

SCHEMA_VERSION = "1.0"

# Each entry: (field_path, type, required, description)
FIELD_REFERENCE = [
    # ── Top-level ────────────────────────────────────────────────────────
    ("schema_version",              "string",  True,  "ECS-lite schema version (always 1.0)"),
    ("tags",                        "array",   True,  "Free-form tags (e.g. atomic-test, T1059.001)"),

    # ── event ────────────────────────────────────────────────────────────
    ("event.id",                    "string",  True,  "UUID v4 — unique identifier for this normalized event"),
    ("event.created",               "ISO8601", True,  "Timestamp the event was created (UTC)"),
    ("event.source_type",           "string",  True,  "Source adapter: sysmon | wel | wazuh | syslog | cef"),
    ("event.category",              "array",   False, "ECS category: process | network | file | registry | authentication | iam | driver"),
    ("event.type",                  "array",   False, "ECS type: start | end | creation | deletion | access | change | connection | protocol | info"),
    ("event.action",                "string",  False, "Human-readable action description from the source log"),
    ("event.outcome",               "string",  False, "success | failure | unknown"),
    ("event.severity",              "integer", False, "Normalized 0–100 severity score (maps from source level)"),
    ("event.original_event_id",     "string",  False, "Event ID from the source (e.g. Sysmon EventID or WEL Id)"),

    # ── host ─────────────────────────────────────────────────────────────
    ("host.name",                   "string",  False, "Hostname of the originating endpoint"),
    ("host.hostname",               "string",  False, "Hostname (same as host.name)"),
    ("host.ip",                     "array",   False, "List of IP addresses associated with the host"),
    ("host.os.type",                "string",  False, "OS family: windows | linux | macos"),
    ("host.os.name",                "string",  False, "Full OS name (e.g. Windows 11 Pro)"),

    # ── process ──────────────────────────────────────────────────────────
    ("process.pid",                 "integer", False, "Process ID"),
    ("process.ppid",                "integer", False, "Parent process ID"),
    ("process.name",                "string",  False, "Process image name (e.g. powershell.exe)"),
    ("process.executable",          "string",  False, "Full path to the process executable"),
    ("process.command_line",        "string",  False, "Full command line including arguments"),
    ("process.hash.md5",            "string",  False, "MD5 hash of the process image (lowercase hex)"),
    ("process.hash.sha256",         "string",  False, "SHA-256 hash of the process image (lowercase hex)"),
    ("process.parent.pid",          "integer", False, "Parent process PID"),
    ("process.parent.name",         "string",  False, "Parent process image name"),
    ("process.parent.executable",   "string",  False, "Full path to the parent process executable"),
    ("process.parent.command_line", "string",  False, "Parent process command line"),

    # ── network ──────────────────────────────────────────────────────────
    ("network.direction",           "string",  False, "Traffic direction: ingress | egress | internal"),
    ("network.transport",           "string",  False, "Transport protocol: tcp | udp | icmp"),
    ("network.protocol",            "string",  False, "Application protocol (same as transport when unknown)"),
    ("network.destination.ip",      "string",  False, "Destination IP address"),
    ("network.destination.port",    "integer", False, "Destination port"),
    ("network.destination.domain",  "string",  False, "Destination domain / hostname"),
    ("network.source.ip",           "string",  False, "Source IP address"),
    ("network.source.port",         "integer", False, "Source port"),

    # ── file ─────────────────────────────────────────────────────────────
    ("file.path",                   "string",  False, "Full file path"),
    ("file.name",                   "string",  False, "File name without directory"),
    ("file.extension",              "string",  False, "File extension without leading dot"),
    ("file.hash.md5",               "string",  False, "MD5 hash (lowercase hex)"),
    ("file.hash.sha256",            "string",  False, "SHA-256 hash (lowercase hex)"),
    ("file.size",                   "integer", False, "File size in bytes"),

    # ── registry ─────────────────────────────────────────────────────────
    ("registry.path",               "string",  False, "Full registry path (hive + key + value)"),
    ("registry.key",                "string",  False, "Registry key name"),
    ("registry.value.name",         "string",  False, "Registry value name"),
    ("registry.value.type",         "string",  False, "Registry value type (REG_SZ, REG_DWORD, …)"),
    ("registry.value.data",         "string",  False, "Registry value data"),

    # ── user ─────────────────────────────────────────────────────────────
    ("user.name",                   "string",  False, "Account username"),
    ("user.domain",                 "string",  False, "Account domain or workgroup"),
    ("user.id",                     "string",  False, "Account SID or UID"),

    # ── log ──────────────────────────────────────────────────────────────
    ("log.source_type",             "string",  True,  "Adapter used: sysmon | wel | wazuh | syslog | cef"),
    ("log.source_tool",             "string",  False, "Tool that generated the original log"),
    ("log.original_event_id",       "string",  False, "Original event identifier before normalization"),
    ("log.original_log",            "object",  False, "Raw source record preserved verbatim"),
]

# Source type descriptions for the UI
SOURCE_DESCRIPTIONS = {
    "sysmon": {
        "label":       "Sysmon XML",
        "description": "Microsoft Sysinternals Sysmon event log exported as XML "
                       "(wevtutil qe Microsoft-Windows-Sysmon/Operational /f:xml)",
        "events":      "EventIDs 1–29 (process creation, network, file, registry, DNS, WMI, pipes)",
        "icon":        "W",
        "color":       "blue",
    },
    "wel": {
        "label":       "Windows Event Log CSV",
        "description": "Security.evtx or System.evtx exported to CSV via Get-WinEvent or wevtutil",
        "events":      "4624/4625 logon, 4688 process, 4698 tasks, 4720/4726 accounts, 4740 lockout",
        "icon":        "W",
        "color":       "blue",
    },
    "wazuh": {
        "label":       "Wazuh Alerts JSON",
        "description": "Wazuh alerts.json (NDJSON) or single-alert JSON from the Wazuh API",
        "events":      "All Wazuh rule-based alerts with agent, rule, and data fields",
        "icon":        "W",
        "color":       "orange",
    },
    "syslog": {
        "label":       "Linux auth.log / syslog",
        "description": "/var/log/auth.log, /var/log/syslog, or journald text exports",
        "events":      "SSH logins, sudo, PAM, cron, useradd, su, systemd",
        "icon":        "L",
        "color":       "green",
    },
    "cef": {
        "label":       "CEF / Generic JSON",
        "description": "Common Event Format (CEF:0|...) or generic JSON with best-effort field mapping",
        "events":      "Vendor-agnostic — maps src, dst, act, msg fields to ECS-lite",
        "icon":        "C",
        "color":       "purple",
    },
}
