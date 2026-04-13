"""
CEF / Generic JSON adapter.

Handles two formats:

1. Common Event Format (CEF):
   CEF:0|Vendor|Product|Version|ID|Name|Severity|extensions
   Extensions: key=value pairs (space-separated, values can be quoted)

2. Generic JSON:
   Best-effort field mapping from any flat or moderately nested JSON.
   Maps common field names (src, dst, srcip, dstip, act, msg, etc.)
   to ECS-lite.  Designed as the extensible fallback for any log source
   not covered by dedicated adapters.

Input can be:
  - A single CEF line
  - Multiple CEF lines (one per line)
  - A JSON object or JSON array
  - NDJSON (one JSON object per line)
"""

import json
import logging
import re
from typing import Optional

from adapters.base import BaseAdapter
from core.models import make_ecs_event, safe_int

logger = logging.getLogger(__name__)

# CEF header pattern
_CEF_HEADER = re.compile(
    r"^CEF:(?P<version>\d+)\|"
    r"(?P<vendor>[^|]*)\|"
    r"(?P<product>[^|]*)\|"
    r"(?P<prod_version>[^|]*)\|"
    r"(?P<signature_id>[^|]*)\|"
    r"(?P<name>[^|]*)\|"
    r"(?P<severity>[^|]*)\|"
    r"(?P<extensions>.*)$",
    re.IGNORECASE,
)

# CEF severity (0–10) → ECS severity (0–100)
def _cef_sev(raw: str) -> int:
    n = safe_int(raw, 0)
    return min(100, n * 10)

def _parse_cef_extensions(ext: str) -> dict:
    """
    Parse CEF key=value extensions into a dict.
    Handles spaces in values when preceded by another key=.
    """
    result = {}
    # Split on word= pattern
    parts = re.split(r"(?<!\w)(\w+)=", " " + ext)
    keys = parts[1::2]
    vals = parts[2::2]
    for k, v in zip(keys, vals):
        result[k.strip()] = v.strip()
    return result


# Generic JSON field name aliases → ECS-lite param
_JSON_FIELD_MAP = {
    # time
    "timestamp":        "created",
    "time":             "created",
    "@timestamp":       "created",
    "datetime":         "created",
    "eventtime":        "created",
    # host
    "hostname":         "host_name",
    "host":             "host_name",
    "device_hostname":  "host_name",
    "computername":     "host_name",
    "computer":         "host_name",
    # source network
    "src":              "src_ip",
    "srcip":            "src_ip",
    "src_ip":           "src_ip",
    "sourceaddress":    "src_ip",
    "source_ip":        "src_ip",
    "spt":              "src_port",
    "srcport":          "src_port",
    "src_port":         "src_port",
    # destination network
    "dst":              "dst_ip",
    "dstip":            "dst_ip",
    "dst_ip":           "dst_ip",
    "destinationaddress": "dst_ip",
    "destination_ip":   "dst_ip",
    "dpt":              "dst_port",
    "dstport":          "dst_port",
    "dst_port":         "dst_port",
    "destinationport":  "dst_port",
    "destination_domain": "dst_domain",
    "destinationhostname": "dst_domain",
    # transport
    "proto":            "net_transport",
    "protocol":         "net_transport",
    "transport":        "net_transport",
    # action / description
    "act":              "action",
    "action":           "action",
    "msg":              "action",
    "message":          "action",
    "description":      "action",
    "eventdescription": "action",
    "name":             "action",
    # user
    "suser":            "user_name",
    "duser":            "user_name",
    "username":         "user_name",
    "user":             "user_name",
    "account":          "user_name",
    "subject_user_name":"user_name",
    # process
    "sproc":            "process_name",
    "dproc":            "process_name",
    "process":          "process_name",
    "processname":      "process_name",
    "pid":              "process_pid",
    "spid":             "process_pid",
    "dpid":             "process_pid",
    "cmd":              "process_cmdline",
    "command":          "process_cmdline",
    "commandline":      "process_cmdline",
    # file
    "fname":            "file_name",
    "filename":         "file_name",
    "filepath":         "file_path",
    "file_path":        "file_path",
    "filehash":         "file_sha256",
    # severity
    "severity":         "severity",
    "level":            "severity",
    "priority":         "severity",
    # outcome
    "outcome":          "outcome",
    "result":           "outcome",
    "status":           "outcome",
}


def _extract_json_fields(obj: dict) -> dict:
    """Flatten and map a generic JSON object to ECS-lite kwargs."""
    params: dict = {}
    for raw_key, raw_val in obj.items():
        key = raw_key.lower().replace("-", "_").replace(" ", "_")
        mapped = _JSON_FIELD_MAP.get(key)
        if mapped and raw_val is not None:
            params[mapped] = str(raw_val).strip()
    # Numeric coercions
    for int_field in ("src_port", "dst_port", "process_pid", "severity"):
        if int_field in params:
            params[int_field] = safe_int(params[int_field])
    # Outcome normalisation
    if "outcome" in params:
        o = params["outcome"].lower()
        if o in ("success", "allow", "allowed", "permit", "pass", "0"):
            params["outcome"] = "success"
        elif o in ("failure", "fail", "failed", "deny", "denied", "block", "blocked",
                   "drop", "reject", "rejected", "error"):
            params["outcome"] = "failure"
        else:
            params["outcome"] = "unknown"
    return params


class CEFAdapter(BaseAdapter):
    source_type = "cef"

    def _parse_records(self, raw: str) -> list:
        raw = raw.strip()
        if not raw:
            return []

        records = []

        # Try JSON first
        if raw.startswith("{"):
            try:
                obj = json.loads(raw)
                if isinstance(obj, dict):
                    return [{"_format": "json", "_data": obj}]
            except json.JSONDecodeError:
                pass
        if raw.startswith("["):
            try:
                arr = json.loads(raw)
                if isinstance(arr, list):
                    return [{"_format": "json", "_data": o} for o in arr if isinstance(o, dict)]
            except json.JSONDecodeError:
                pass

        # Line-by-line: CEF or NDJSON
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.upper().startswith("CEF:"):
                records.append({"_format": "cef", "_data": line})
            elif line.startswith("{"):
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        records.append({"_format": "json", "_data": obj})
                except json.JSONDecodeError:
                    logger.debug("CEF/JSON line not parseable: %r", line[:80])
            # else skip unrecognised lines
        return records

    def _normalize_record(self, rec: dict) -> Optional[dict]:
        fmt  = rec.get("_format", "cef")
        data = rec.get("_data")

        if fmt == "cef" and isinstance(data, str):
            return self._normalize_cef(data)
        if fmt == "json" and isinstance(data, dict):
            return self._normalize_json(data)
        return None

    def _normalize_cef(self, line: str) -> Optional[dict]:
        m = _CEF_HEADER.match(line)
        if not m:
            return None
        vendor  = m.group("vendor")
        product = m.group("product")
        sig_id  = m.group("signature_id")
        name    = m.group("name")
        raw_sev = m.group("severity")
        ext_str = m.group("extensions")

        ext = _parse_cef_extensions(ext_str)
        params = _extract_json_fields(ext)

        severity = _cef_sev(raw_sev)
        if "severity" in params:
            severity = min(100, params.pop("severity") or severity)

        action   = params.pop("action", "") or name
        created  = params.pop("created", None)
        host_name = params.pop("host_name", "")
        src_ip   = params.pop("src_ip", "")
        src_port = params.pop("src_port", None)
        dst_ip   = params.pop("dst_ip", "")
        dst_port = params.pop("dst_port", None)
        dst_domain = params.pop("dst_domain", "")
        transport = params.pop("net_transport", "")
        user_name = params.pop("user_name", "")
        process_name = params.pop("process_name", "")
        process_pid  = params.pop("process_pid", None)
        cmdline  = params.pop("process_cmdline", "")
        file_name = params.pop("file_name", "")
        file_path = params.pop("file_path", "")
        outcome  = params.pop("outcome", "unknown")

        # Category inference from vendor/product/action
        category, etype = _infer_cef_category(vendor, product, action, src_ip, dst_ip)

        return make_ecs_event(
            source_type       = "cef",
            source_tool       = f"{vendor}/{product}".strip("/"),
            created           = created,
            category          = category,
            event_type        = etype,
            action            = action,
            outcome           = outcome,
            severity          = severity,
            original_event_id = sig_id,
            host_name         = host_name,
            process_name      = process_name,
            process_pid       = process_pid,
            process_cmdline   = cmdline,
            net_transport     = transport.lower() if transport else "",
            dst_ip            = dst_ip,
            dst_port          = dst_port,
            dst_domain        = dst_domain,
            src_ip            = src_ip,
            src_port          = src_port,
            file_path         = file_path,
            file_name         = file_name,
            user_name         = user_name,
            tags              = [],
            original_log      = {"vendor": vendor, "product": product,
                                  "sig_id": sig_id, "name": name,
                                  "raw_severity": raw_sev},
        )

    def _normalize_json(self, obj: dict) -> Optional[dict]:
        params = _extract_json_fields(obj)

        action   = params.pop("action", "")
        created  = params.pop("created", None)
        host_name = params.pop("host_name", "")
        src_ip   = params.pop("src_ip", "")
        src_port = params.pop("src_port", None)
        dst_ip   = params.pop("dst_ip", "")
        dst_port = params.pop("dst_port", None)
        dst_domain = params.pop("dst_domain", "")
        transport = params.pop("net_transport", "")
        user_name = params.pop("user_name", "")
        process_name = params.pop("process_name", "")
        process_pid  = params.pop("process_pid", None)
        cmdline  = params.pop("process_cmdline", "")
        file_name = params.pop("file_name", "")
        file_path = params.pop("file_path", "")
        file_sha256 = params.pop("file_sha256", "")
        outcome  = params.pop("outcome", "unknown")
        severity = params.pop("severity", 0) or 0

        category, etype = _infer_cef_category("", "", action, src_ip, dst_ip)

        return make_ecs_event(
            source_type       = "cef",
            source_tool       = "generic-json",
            created           = created,
            category          = category,
            event_type        = etype,
            action            = action,
            outcome           = outcome,
            severity          = severity,
            host_name         = host_name,
            process_name      = process_name,
            process_pid       = process_pid,
            process_cmdline   = cmdline,
            net_transport     = transport.lower() if transport else "",
            dst_ip            = dst_ip,
            dst_port          = dst_port,
            dst_domain        = dst_domain,
            src_ip            = src_ip,
            src_port          = src_port,
            file_path         = file_path,
            file_name         = file_name,
            file_sha256       = file_sha256,
            user_name         = user_name,
            tags              = [],
            original_log      = obj,
        )


def _infer_cef_category(vendor: str, product: str, action: str,
                         src_ip: str, dst_ip: str) -> tuple:
    """Heuristic category inference for CEF/JSON records."""
    combined = f"{vendor} {product} {action}".lower()
    if any(k in combined for k in ("firewall", "fw", "network", "traffic",
                                    "connection", "flow", "netflow")):
        cat = ["network"]
        typ = ["connection"] if (src_ip or dst_ip) else ["info"]
    elif any(k in combined for k in ("login", "logon", "auth", "password",
                                      "credential", "session")):
        cat = ["authentication"]
        typ = ["start"]
    elif any(k in combined for k in ("process", "execut", "spawn", "cmd",
                                      "command", "powershell", "script")):
        cat = ["process"]
        typ = ["start"]
    elif any(k in combined for k in ("file", "document", "upload", "download",
                                      "write", "delete", "creat")):
        cat = ["file"]
        typ = ["change"]
    elif any(k in combined for k in ("malware", "virus", "threat", "detect",
                                      "intrusion", "exploit", "attack")):
        cat = ["intrusion_detection"]
        typ = ["info"]
    else:
        cat = ["network"] if (src_ip or dst_ip) else ["process"]
        typ = ["info"]
    return cat, typ
