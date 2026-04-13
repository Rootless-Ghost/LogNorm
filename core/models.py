"""
LogNorm core models.

Provides make_ecs_event() — the single factory function all adapters
call to produce a well-structured ECS-lite event dict.

Schema version: 1.0
Required fields: event.id, event.created, log.source_type
All other fields are optional and omitted when empty/None.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional


SCHEMA_VERSION = "1.0"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def make_ecs_event(
    source_type: str,
    *,
    # ── event context ──────────────────────────────────────────────
    event_id: Optional[str]       = None,
    created: Optional[str]        = None,
    category: Optional[list]      = None,
    event_type: Optional[list]    = None,
    action: str                   = "",
    outcome: str                  = "unknown",
    severity: int                 = 0,
    original_event_id: str        = "",
    # ── host ───────────────────────────────────────────────────────
    host_name: str                = "",
    host_ip: Optional[list]       = None,
    os_type: str                  = "",
    os_name: str                  = "",
    # ── process ────────────────────────────────────────────────────
    process_pid: Optional[int]    = None,
    process_ppid: Optional[int]   = None,
    process_name: str             = "",
    process_exe: str              = "",
    process_cmdline: str          = "",
    process_md5: str              = "",
    process_sha256: str           = "",
    parent_pid: Optional[int]     = None,
    parent_name: str              = "",
    parent_exe: str               = "",
    parent_cmdline: str           = "",
    # ── network ────────────────────────────────────────────────────
    net_direction: str            = "",
    net_transport: str            = "",
    dst_ip: str                   = "",
    dst_port: Optional[int]       = None,
    dst_domain: str               = "",
    src_ip: str                   = "",
    src_port: Optional[int]       = None,
    # ── file ───────────────────────────────────────────────────────
    file_path: str                = "",
    file_name: str                = "",
    file_ext: str                 = "",
    file_md5: str                 = "",
    file_sha256: str              = "",
    file_size: Optional[int]      = None,
    # ── registry ───────────────────────────────────────────────────
    reg_path: str                 = "",
    reg_key: str                  = "",
    reg_value_name: str           = "",
    reg_value_type: str           = "",
    reg_value_data: str           = "",
    # ── user ───────────────────────────────────────────────────────
    user_name: str                = "",
    user_domain: str              = "",
    user_id: str                  = "",
    # ── log metadata ───────────────────────────────────────────────
    source_tool: str              = "",
    original_log: Optional[dict]  = None,
    # ── tags ───────────────────────────────────────────────────────
    tags: Optional[list]          = None,
) -> dict:
    """
    Build and return an ECS-lite event dict.

    Only populated sections are included (except event, log, tags which
    are always present).  Required fields event.id, event.created, and
    log.source_type are always set.
    """
    event: dict = {
        "id":        event_id or str(uuid.uuid4()),
        "created":   created or _now_iso(),
        "outcome":   outcome,
        "severity":  severity,
        "source_type": source_type,
    }
    if category:
        event["category"] = category
    if event_type:
        event["type"] = event_type
    if action:
        event["action"] = action
    if original_event_id:
        event["original_event_id"] = original_event_id

    result: dict = {
        "schema_version": SCHEMA_VERSION,
        "event": event,
    }

    # ── host ──────────────────────────────────────────────────────
    host: dict = {}
    if host_name:
        host["name"] = host_name
        host["hostname"] = host_name
    if host_ip:
        host["ip"] = host_ip
    if os_type or os_name:
        host["os"] = {}
        if os_type:
            host["os"]["type"] = os_type
        if os_name:
            host["os"]["name"] = os_name
    if host:
        result["host"] = host

    # ── process ───────────────────────────────────────────────────
    proc: dict = {}
    if process_pid is not None:
        proc["pid"] = process_pid
    if process_ppid is not None:
        proc["ppid"] = process_ppid
    if process_name:
        proc["name"] = process_name
    if process_exe:
        proc["executable"] = process_exe
    if process_cmdline:
        proc["command_line"] = process_cmdline
    if process_md5 or process_sha256:
        hashes: dict = {}
        if process_md5:
            hashes["md5"] = process_md5.lower()
        if process_sha256:
            hashes["sha256"] = process_sha256.lower()
        proc["hash"] = hashes

    parent: dict = {}
    if parent_pid is not None:
        parent["pid"] = parent_pid
    if parent_name:
        parent["name"] = parent_name
    if parent_exe:
        parent["executable"] = parent_exe
    if parent_cmdline:
        parent["command_line"] = parent_cmdline
    if parent:
        proc["parent"] = parent

    if proc:
        result["process"] = proc

    # ── network ───────────────────────────────────────────────────
    net: dict = {}
    if net_direction:
        net["direction"] = net_direction
    if net_transport:
        net["transport"] = net_transport
        net["protocol"] = net_transport
    dst: dict = {}
    if dst_ip:
        dst["ip"] = dst_ip
    if dst_port is not None:
        dst["port"] = dst_port
    if dst_domain:
        dst["domain"] = dst_domain
    if dst:
        net["destination"] = dst
    src: dict = {}
    if src_ip:
        src["ip"] = src_ip
    if src_port is not None:
        src["port"] = src_port
    if src:
        net["source"] = src
    if net:
        result["network"] = net

    # ── file ──────────────────────────────────────────────────────
    fobj: dict = {}
    if file_path:
        fobj["path"] = file_path
    if file_name:
        fobj["name"] = file_name
    if file_ext:
        fobj["extension"] = file_ext
    if file_md5 or file_sha256:
        fhashes: dict = {}
        if file_md5:
            fhashes["md5"] = file_md5.lower()
        if file_sha256:
            fhashes["sha256"] = file_sha256.lower()
        fobj["hash"] = fhashes
    if file_size is not None:
        fobj["size"] = file_size
    if fobj:
        result["file"] = fobj

    # ── registry ──────────────────────────────────────────────────
    reg: dict = {}
    if reg_path:
        reg["path"] = reg_path
    if reg_key:
        reg["key"] = reg_key
    if reg_value_name or reg_value_type or reg_value_data:
        reg["value"] = {}
        if reg_value_name:
            reg["value"]["name"] = reg_value_name
        if reg_value_type:
            reg["value"]["type"] = reg_value_type
        if reg_value_data:
            reg["value"]["data"] = reg_value_data
    if reg:
        result["registry"] = reg

    # ── user ──────────────────────────────────────────────────────
    user: dict = {}
    if user_name:
        user["name"] = user_name
    if user_domain:
        user["domain"] = user_domain
    if user_id:
        user["id"] = user_id
    if user:
        result["user"] = user

    # ── log metadata ──────────────────────────────────────────────
    log: dict = {
        "source_type": source_type,
        "source_tool": source_tool or source_type,
    }
    if original_event_id:
        log["original_event_id"] = original_event_id
    if original_log:
        log["original_log"] = original_log
    result["log"] = log

    # ── tags ──────────────────────────────────────────────────────
    result["tags"] = tags or []

    return result


def parse_hash_string(hash_str: str) -> tuple[str, str]:
    """
    Parse a Sysmon-style hash string like 'MD5=abc,SHA256=def,...'
    and return (md5, sha256).
    """
    md5 = sha256 = ""
    for part in hash_str.split(","):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            k = k.strip().upper()
            v = v.strip()
            if k == "MD5":
                md5 = v
            elif k in ("SHA256", "SHA-256"):
                sha256 = v
    return md5, sha256


def safe_int(value, default=None) -> Optional[int]:
    """Convert value to int, returning default on failure."""
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default
