"""Inspect/apply C0-C3 and read/export the decoy's PostgreSQL JSON log.

Run from the repository root with python3 -m lab.logging. This always targets
lab/compose.yml, never the main bank's PostgreSQL 13 compose project.
"""
import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from lab.run import COMMON, CONFIGS, configure, current_log, docker, sql

STARTUP = ("shared_preload_libraries", "logging_collector", "log_destination",
           "log_directory", "log_filename", "log_timezone")


def snapshot():
    names = sorted(set(COMMON) | set(STARTUP))
    settings = json.loads(sql(
        "SELECT json_object_agg(name, json_build_object('value', setting, 'source', source, "
        "'pending_restart', pending_restart)) FROM pg_settings WHERE name IN ("
        + ",".join("'" + name + "'" for name in names) + ");"))
    info = json.loads(sql(
        "SELECT json_build_object('server_version_num', current_setting('server_version_num')::int, "
        "'pgaudit_version', (SELECT extversion FROM pg_extension WHERE extname='pgaudit'), "
        "'current_json_log', pg_current_logfile('jsonlog'));"))
    matching = [name for name, overrides in CONFIGS.items() if all(
        settings.get(key, {}).get("value") == value for key, value in {**COMMON, **overrides}.items())]
    return {**info, "compose_file": "lab/compose.yml", "matching_profiles": matching,
            "settings": settings}


def preflight(state):
    if not 160000 <= state["server_version_num"] < 170000:
        raise RuntimeError("This lab helper requires the dedicated PostgreSQL 16 decoy; no settings changed.")
    settings = state["settings"]
    required = {"logging_collector": "on", "log_timezone": "UTC"}
    for key, value in required.items():
        if settings.get(key, {}).get("value") != value:
            raise RuntimeError(f"Expected {key}={value}. Start db using lab/compose.yml first; no settings changed.")
    libraries = [part.strip() for part in settings.get("shared_preload_libraries", {}).get("value", "").split(",")]
    destinations = [part.strip() for part in settings.get("log_destination", {}).get("value", "").split(",")]
    if "pgaudit" not in libraries or "jsonlog" not in destinations or not state["current_json_log"]:
        raise RuntimeError("pgAudit preload / JSON logging is not ready. Check lab/compose.yml; no settings changed.")
    if any(settings.get(key, {}).get("pending_restart") for key in STARTUP):
        raise RuntimeError("Startup log settings have a pending restart. Resolve them before applying a profile.")


def export_log(directory):
    """Rotate, wait for a different file, then copy the closed previous file."""
    before = current_log()
    time.sleep(1.1)  # filename precision is seconds
    sql("SELECT pg_rotate_logfile();")
    for _ in range(50):
        if current_log() != before:
            break
        time.sleep(.1)
    else:
        raise RuntimeError("Log rotation did not finish; refusing to export an active file")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    destination = Path(directory) / stamp
    destination.mkdir(parents=True, exist_ok=False)
    docker("cp", "db:" + before, str((destination / "postgres.jsonl").resolve()))
    (destination / "settings.json").write_text(json.dumps(snapshot(), indent=2), encoding="utf-8")
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", choices=CONFIGS, help="Apply profile; briefly stop/start decoy web to refresh its pool")
    parser.add_argument("--tail", type=int, metavar="N", help="Print last N lines of the current JSON log")
    parser.add_argument("--export-dir", type=Path, help="Rotate and export the previous file and settings into a new timestamp directory")
    args = parser.parse_args()
    if args.tail is not None and args.tail < 1:
        parser.error("--tail must be positive")
    try:
        state = snapshot()
        preflight(state)
        if args.apply:
            # CREATE EXTENSION is required before enabling audit, including on an
            # existing lab volume that predates init.sql. Do not drop/recreate it.
            sql("CREATE EXTENSION IF NOT EXISTS pgaudit;")
            print(f"Applying {args.apply}; restarting decoy web only to refresh pooled sessions...", flush=True)
            configure(args.apply)
            state = snapshot()
            if state["matching_profiles"] != [args.apply]:
                raise RuntimeError("Effective settings do not match the requested profile")
        print(json.dumps(state, ensure_ascii=False, indent=2))
        if args.tail:
            print(docker("exec", "-T", "db", "tail", "-n", str(args.tail), current_log()), end="")
        if args.export_dir:
            print("Exported: " + str(export_log(args.export_dir)))
    except (OSError, RuntimeError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    main()
