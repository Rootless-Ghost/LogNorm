"""
LogNorm CLI — standalone log normalizer.

Usage
-----
Normalize a Sysmon XML export:
    python cli.py --input sysmon.xml --source sysmon

Normalize a WEL CSV and write to file:
    python cli.py --input security.csv --source wel --output normalized.json

Normalize Wazuh alerts to CSV:
    python cli.py --input alerts.json --source wazuh --output out.csv --format csv

Normalize auth.log (stdout, pretty-print):
    python cli.py --input /var/log/auth.log --source syslog --pretty

Read from stdin:
    cat sysmon.xml | python cli.py --source sysmon --stdin

Available source types: sysmon | wel | wazuh | syslog | cef
"""

import argparse
import csv
import json
import logging
import os
import sys

import yaml

# Ensure project root is on sys.path when run directly
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from adapters import get_adapter, SUPPORTED_SOURCES

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("lognorm-cli")


# ── Config ────────────────────────────────────────────────────────────────

_DEFAULTS = {
    "normalization": {"original_log_max_chars": 4096},
}


def _load_config(path: str) -> dict:
    if not path or not os.path.exists(path):
        return _DEFAULTS
    try:
        with open(path, encoding="utf-8") as fh:
            loaded = yaml.safe_load(fh) or {}
        result = dict(_DEFAULTS)
        result.update(loaded)
        return result
    except Exception as exc:
        logger.warning("Could not load config: %s", exc)
        return _DEFAULTS


# ── Helpers ───────────────────────────────────────────────────────────────

def _truncate_original_log(events: list, max_chars: int) -> None:
    if max_chars <= 0:
        return
    for ev in events:
        orig = ev.get("log", {}).get("original_log", {})
        if isinstance(orig, dict):
            for k, v in orig.items():
                if isinstance(v, str) and len(v) > max_chars:
                    orig[k] = v[:max_chars] + "…"


def _to_csv(events: list, fh) -> None:
    headers = [
        "event_id", "created", "source_type", "category", "action",
        "outcome", "severity", "host_name", "user_name",
        "process_name", "process_cmdline", "src_ip", "dst_ip", "dst_port",
        "tags",
    ]
    writer = csv.writer(fh)
    writer.writerow(headers)
    for ev in events:
        e   = ev.get("event", {})
        h   = ev.get("host", {})
        p   = ev.get("process", {})
        net = ev.get("network", {})
        u   = ev.get("user", {})
        writer.writerow([
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


# ── CLI ───────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="LogNorm CLI — normalize log files to ECS-lite JSON/CSV",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--input", "-i", metavar="FILE",
        help="Path to input log file",
    )
    p.add_argument(
        "--stdin", action="store_true",
        help="Read input from stdin instead of a file",
    )
    p.add_argument(
        "--source", "-s", metavar="TYPE", required=True,
        choices=SUPPORTED_SOURCES,
        help=f"Log source type: {' | '.join(SUPPORTED_SOURCES)}",
    )
    p.add_argument(
        "--output", "-o", metavar="FILE",
        help="Output file path (default: stdout)",
    )
    p.add_argument(
        "--format", "-f", default="json", choices=["json", "csv"],
        help="Output format: json (default) or csv",
    )
    p.add_argument(
        "--pretty", action="store_true",
        help="Pretty-print JSON output (ignored for CSV)",
    )
    p.add_argument(
        "--no-original-log", action="store_true",
        help="Strip log.original_log from output to reduce size",
    )
    p.add_argument(
        "--config", metavar="PATH", default="config.yaml",
        help="Path to config.yaml (default: ./config.yaml)",
    )
    p.add_argument(
        "--log-level", default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: WARNING)",
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()
    logging.getLogger().setLevel(args.log_level)

    config = _load_config(args.config)
    max_chars = config.get("normalization", {}).get("original_log_max_chars", 4096)

    # ── Read input ────────────────────────────────────────────────────
    if args.stdin:
        raw = sys.stdin.read()
        input_name = "<stdin>"
    elif args.input:
        if not os.path.exists(args.input):
            print(f"ERROR: File not found: {args.input}", file=sys.stderr)
            sys.exit(1)
        with open(args.input, encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
        input_name = args.input
    else:
        print("ERROR: Provide --input FILE or --stdin", file=sys.stderr)
        sys.exit(1)

    # ── Normalize ─────────────────────────────────────────────────────
    adapter = get_adapter(args.source)
    if adapter is None:
        print(f"ERROR: Unknown source type: {args.source}", file=sys.stderr)
        sys.exit(1)

    events, failed = adapter.parse(raw)

    if max_chars > 0:
        _truncate_original_log(events, max_chars)

    if args.no_original_log:
        for ev in events:
            ev.get("log", {}).pop("original_log", None)

    # ── Banner (stderr so it doesn't pollute pipe output) ─────────────
    print(
        f"LogNorm  source={args.source}  input={input_name}  "
        f"events={len(events)}  failed={failed}",
        file=sys.stderr,
    )

    if not events:
        print("WARNING: No events were normalized from input.", file=sys.stderr)
        sys.exit(0)

    # ── Write output ──────────────────────────────────────────────────
    if args.output:
        out_fh = open(args.output, "w", encoding="utf-8", newline="")
        close_fh = True
    else:
        out_fh = sys.stdout
        close_fh = False

    try:
        if args.format == "csv":
            _to_csv(events, out_fh)
        else:
            indent = 2 if args.pretty else None
            json.dump(events, out_fh, indent=indent, ensure_ascii=False)
            if indent:
                out_fh.write("\n")
    finally:
        if close_fh:
            out_fh.close()

    if args.output:
        print(f"Output written to: {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
