"""
LogNorm — Log Source Normalizer
Sysmon / WEL / Wazuh / syslog / CEF → ECS-lite schema

Author:  Rootless-Ghost
Version: 1.0.0
Port:    5006 (default)

Usage:
    python app.py
    python app.py --port 5006
    python app.py --config /path/to/config.yaml --debug
"""

import argparse
import csv
import io
import json
import logging
import os

import yaml
from flask import Flask, jsonify, render_template, request, send_file

from core.engine import NormalizationEngine
from core.schema import FIELD_REFERENCE, SOURCE_DESCRIPTIONS

# ── Logging ─────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("lognorm")

# ── Config ───────────────────────────────────────────────────────────────

_DEFAULTS: dict = {
    "port":       5006,
    "db_path":    "./lognorm.db",
    "output_dir": "./output",
    "wazuh": {
        "host": "192.168.46.100",
        "port": 55000,
        "user": "wazuh-wui",
    },
    "normalization": {
        "max_file_mb":          50,
        "original_log_max_chars": 4096,
        "auto_save":            True,
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    result = dict(base)
    for key, value in override.items():
        if (isinstance(value, dict)
                and key in result
                and isinstance(result[key], dict)):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(path: str) -> dict:
    config = _deep_merge({}, _DEFAULTS)
    if not os.path.exists(path):
        logger.warning("Config not found: %s — using defaults", path)
        return config
    try:
        with open(path, encoding="utf-8") as fh:
            loaded = yaml.safe_load(fh) or {}
        config = _deep_merge(config, loaded)
    except Exception as exc:
        logger.error("Failed to load config: %s — using defaults", exc)
    return config


# ── App factory ───────────────────────────────────────────────────────────

app = Flask(__name__)
_config: dict = {}
_engine: NormalizationEngine = None  # type: ignore


def create_app(config_path: str = "config.yaml") -> Flask:
    global _config, _engine
    _config = load_config(config_path)
    _engine = NormalizationEngine(_config)
    return app


# ── Helper: max file size ─────────────────────────────────────────────────

def _max_bytes() -> int:
    mb = _config.get("normalization", {}).get("max_file_mb", 50)
    return int(mb) * 1024 * 1024


# ── Page routes ───────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html",
                           sources=_engine.get_sources(),
                           source_descriptions=SOURCE_DESCRIPTIONS)


@app.route("/records")
def records_page():
    return render_template("records.html",
                           sources=_engine.get_sources())


@app.route("/schema")
def schema_page():
    return render_template("schema.html",
                           fields=FIELD_REFERENCE,
                           source_descriptions=SOURCE_DESCRIPTIONS)


# ── API: health ───────────────────────────────────────────────────────────

@app.route("/api/health")
def api_health():
    return jsonify({"status": "ok", "tool": "lognorm", "version": "1.0.0"})


# ── API: sources ──────────────────────────────────────────────────────────

@app.route("/api/sources")
def api_sources():
    return jsonify({
        "sources": _engine.get_sources(),
        "descriptions": SOURCE_DESCRIPTIONS,
    })


# ── API: normalize (single record, JSON body) ─────────────────────────────

@app.route("/api/normalize", methods=["POST"])
def api_normalize():
    """
    Normalize a single raw record.

    Body: {"source_type": "sysmon", "raw": "<Event>...</Event>"}
    Returns: {"success": true, "event": {<ECS-lite>}, "session_id": "..."}
    """
    body = request.get_json(silent=True) or {}
    source_type = (body.get("source_type") or "").strip().lower()
    raw         = body.get("raw") or ""

    if not source_type:
        return jsonify({"success": False, "error": "source_type is required"}), 400
    if not raw:
        return jsonify({"success": False, "error": "raw is required"}), 400

    result = _engine.normalize_text(raw, source_type)

    if not result["success"]:
        return jsonify(result), 400

    events = result["events"]
    if not events:
        return jsonify({
            "success": False,
            "error": "No events parsed from input",
            "failed": result["failed"],
        }), 422

    return jsonify({
        "success":    True,
        "event":      events[0],
        "session_id": result["session_id"],
        "source_type": source_type,
    })


# ── API: normalize/batch ──────────────────────────────────────────────────

@app.route("/api/normalize/batch", methods=["POST"])
def api_normalize_batch():
    """
    Normalize a batch of records.

    Accepts two content types:
      1. multipart/form-data: file (upload) + source_type (field)
      2. application/json:    {"source_type": "...", "records": ["...", ...]}
                              OR {"source_type": "...", "raw": "...full file content..."}

    Returns:
      {"success": true, "events": [...], "failed": N, "total": N, "session_id": "..."}
    """
    content_type = request.content_type or ""

    # ── File upload ───────────────────────────────────────────────────
    if "multipart/form-data" in content_type:
        source_type = (request.form.get("source_type") or "").strip().lower()
        if not source_type:
            return jsonify({"success": False, "error": "source_type field is required"}), 400

        if "file" not in request.files:
            return jsonify({"success": False, "error": "No file in upload"}), 400

        uploaded = request.files["file"]
        if not uploaded.filename:
            return jsonify({"success": False, "error": "Empty filename"}), 400

        raw_bytes = uploaded.read()
        if len(raw_bytes) > _max_bytes():
            return jsonify({
                "success": False,
                "error": f"File exceeds maximum size of "
                         f"{_config['normalization']['max_file_mb']} MB",
            }), 413

        try:
            raw = raw_bytes.decode("utf-8", errors="replace")
        except Exception as exc:
            app.logger.exception("Failed to decode uploaded file as UTF-8")
            return jsonify({"success": False, "error": "Could not decode uploaded file"}), 400

        result = _engine.normalize_text(raw, source_type,
                                         filename=uploaded.filename)
        if not result["success"]:
            return jsonify(result), 400
        return jsonify({
            "success":    True,
            "events":     result["events"],
            "failed":     result["failed"],
            "total":      result["total"],
            "session_id": result["session_id"],
            "source_type": source_type,
            "filename":    uploaded.filename,
        })

    # ── JSON body ─────────────────────────────────────────────────────
    body = request.get_json(silent=True) or {}
    source_type = (body.get("source_type") or "").strip().lower()
    if not source_type:
        return jsonify({"success": False, "error": "source_type is required"}), 400

    raw = ""
    if "raw" in body:
        raw = body["raw"]
    elif "records" in body:
        records = body["records"]
        if not isinstance(records, list):
            return jsonify({"success": False, "error": "records must be a list"}), 400
        raw = "\n".join(str(r) for r in records)
    else:
        return jsonify({"success": False,
                        "error": "Provide 'raw' (full content) or 'records' (list)"}), 400

    result = _engine.normalize_text(raw, source_type)
    if not result["success"]:
        return jsonify(result), 400
    return jsonify({
        "success":    True,
        "events":     result["events"],
        "failed":     result["failed"],
        "total":      result["total"],
        "session_id": result["session_id"],
        "source_type": source_type,
    })


# ── API: records (list) ───────────────────────────────────────────────────

@app.route("/api/records")
def api_records():
    """
    List stored normalized events with pagination and optional filters.

    Query params: page, per_page, source_type, host, search, session_id
    """
    page        = max(1, int(request.args.get("page", 1)))
    per_page    = max(1, min(200, int(request.args.get("per_page", 50))))
    source_type = request.args.get("source_type", "")
    host        = request.args.get("host", "")
    search      = request.args.get("search", "")
    session_id  = request.args.get("session_id", "")

    result = _engine.get_records(
        page=page, per_page=per_page,
        source_type=source_type, host_name=host,
        search=search, session_id=session_id,
    )
    return jsonify(result)


# ── API: single record ────────────────────────────────────────────────────

@app.route("/api/record/<event_id>")
def api_record(event_id: str):
    event = _engine.get_record(event_id)
    if event is None:
        return jsonify({"success": False, "error": "Event not found"}), 404
    return jsonify({"success": True, "event": event})


# ── API: sessions ─────────────────────────────────────────────────────────

@app.route("/api/sessions")
def api_sessions():
    limit = max(1, min(200, int(request.args.get("limit", 50))))
    return jsonify({"sessions": _engine.get_sessions(limit)})


# ── API: export ───────────────────────────────────────────────────────────

@app.route("/api/export")
def api_export():
    """
    Export normalized events.

    Query params:
      format=json|csv   (default: json)
      session_id=<uuid> (optional — exports all if omitted)
    """
    fmt        = request.args.get("format", "json").lower()
    session_id = request.args.get("session_id", "")

    if fmt == "csv":
        headers, rows = _engine.export_csv_rows(session_id)
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(headers)
        writer.writerows(rows)
        csv_bytes = output.getvalue().encode("utf-8")
        suffix = f"_{session_id[:8]}" if session_id else ""
        fname  = f"lognorm_export{suffix}.csv"
        return send_file(
            io.BytesIO(csv_bytes),
            mimetype="text/csv",
            as_attachment=True,
            download_name=fname,
        )

    # JSON export
    events = _engine.export_json(session_id)
    suffix = f"_{session_id[:8]}" if session_id else ""
    fname  = f"lognorm_export{suffix}.json"
    json_bytes = json.dumps(events, indent=2, ensure_ascii=False).encode("utf-8")
    return send_file(
        io.BytesIO(json_bytes),
        mimetype="application/json",
        as_attachment=True,
        download_name=fname,
    )


# ── API: clear all records ────────────────────────────────────────────────

@app.route("/api/records", methods=["DELETE"])
def api_records_delete():
    count = _engine.clear_all()
    return jsonify({"success": True, "deleted": count})


# ── CLI entry point ───────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="LogNorm — Flask web app")
    p.add_argument("--config",    default="config.yaml")
    p.add_argument("--port",      type=int, default=None)
    p.add_argument("--debug",     action="store_true")
    p.add_argument("--log-level", default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return p.parse_args()


def main() -> None:
    args = parse_args()
    logging.getLogger().setLevel(args.log_level)
    create_app(args.config)
    port = args.port if args.port is not None else int(_config.get("port", 5006))
    logger.info("LogNorm starting on http://0.0.0.0:%d", port)
    app.run(debug=args.debug, host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
