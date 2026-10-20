"""Run C0-C3, preserving all artifacts under lab/results/<run-id>."""
import argparse
import json
import math
import os
import platform
import shutil
import statistics
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from lab.scenarios import actions

ROOT = Path(__file__).resolve().parent
COMPOSE = ["docker", "compose", "-f", str(ROOT / "compose.yml")]
COMMON = {
    "log_statement": "none", "log_min_messages": "warning",
    "log_min_error_statement": "error", "log_connections": "off",
    "log_disconnections": "off", "log_duration": "off",
    "log_min_duration_statement": "-1", "log_parameter_max_length": "-1",
    "log_parameter_max_length_on_error": "0", "pgaudit.log": "none",
    "pgaudit.log_parameter": "off", "pgaudit.log_catalog": "on",
    "pgaudit.log_statement_once": "off", "pgaudit.log_relation": "off",
}
CONFIGS = {
    "C0": {},  # Native defaults: errors, no statement logging.
    "C1": {"log_statement": "all"},
    "C2": {"pgaudit.log": "all", "pgaudit.log_parameter": "on"},
    "C3": {"pgaudit.log": "all", "pgaudit.log_parameter": "on",
           "log_connections": "on", "log_disconnections": "on",
           "log_parameter_max_length_on_error": "-1"},
}


def docker(*args, check=True):
    result = subprocess.run(COMPOSE + list(args), check=False, capture_output=True,
                            text=True, encoding="utf-8")
    if check and result.returncode:
        raise RuntimeError(f"Docker Compose failed ({' '.join(args)}):\n{result.stderr}\n{result.stdout}")
    return result.stdout


def sql(statement):
    return docker("exec", "-T", "db", "psql", "-XAt", "-v", "ON_ERROR_STOP=1",
                  "-U", "postgres", "-d", "vulnerable_bank", "-c", statement)


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def request_json(url, payload=None, headers=None):
    req = urllib.request.Request(url, data=json.dumps(payload).encode() if payload is not None else None,
                                 headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def wait_web(base):
    for _ in range(90):
        try:
            if request_json(base + "/healthz")[0] == 200:
                return
        except (OSError, TimeoutError):
            pass
        time.sleep(1)
    raise RuntimeError("Web not ready: inspect docker compose -f lab/compose.yml logs web")


def configure(name):
    docker("stop", "web")
    expected = {**COMMON, **CONFIGS[name]}
    for key, value in expected.items():
        sql(f"ALTER SYSTEM SET {key} = '{value}';")
    sql("SELECT pg_reload_conf();")
    time.sleep(1)
    actual = json.loads(sql("SELECT json_object_agg(name, setting) FROM pg_settings WHERE name IN ("
                            + ",".join("'" + key + "'" for key in expected) + ");"))
    for key, value in expected.items():
        if actual.get(key) != value:
            raise RuntimeError(f"Config mismatch {key}: expected {value}, got {actual.get(key)}")
    docker("start", "web")
    return actual


def current_log():
    path = sql("SELECT pg_current_logfile('jsonlog');").strip()
    if not path:
        raise RuntimeError("No JSON log file available")
    return path if path.startswith("/") else "/var/lib/postgresql/data/" + path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sessions", type=int, default=6, help="Known test sessions; minimum 2")
    parser.add_argument("--novel-sessions", type=int, default=4)
    parser.add_argument("--build", action="store_true")
    args = parser.parse_args()
    if args.sessions < 2 or args.novel_sessions < 2:
        parser.error("Use at least two sessions per test split")
    if not shutil.which("docker"):
        parser.error("Docker CLI is not installed. Run this command on Ubuntu with Docker Compose v2.")
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output = ROOT / "results" / run_id
    output.mkdir(parents=True)
    base = "http://127.0.0.1:" + os.getenv("LAB_WEB_PORT", "5080")
    # This dedicated compose project has its own database volume.
    print("Starting dedicated lab project (first image build can take several minutes)...", flush=True)
    docker("up", "-d", *(["--build"] if args.build else []), "db", "web")
    wait_web(base)
    write_json(output / "environment.json", {
        "host": platform.platform(), "cpu_count": os.cpu_count(),
        "postgres": sql("SELECT version();").strip(),
        "pgaudit": sql("SELECT extversion FROM pg_extension WHERE extname='pgaudit';").strip(),
        "compose": docker("config"), "images": docker("images", "--format", "json"),
        "sessions": vars(args),
    })
    manifest = []
    # One development session for examples, then separate known/held-out sessions.
    sessions = [("dev", 0)] + [("known", i + 1) for i in range(args.sessions)] + [
        ("novel", i + 100) for i in range(args.novel_sessions)]
    # Interleave sessions deliberately: a pooled DB connection is not an attack session.
    for step in range(8):
        for split, variant in sessions:
            suite = actions(variant, split)
            if step >= len(suite):
                continue
            item = dict(suite[step])
            sid = f"{split}-{variant}"
            manifest.append({**item, "action_id": f"{sid}-{step}", "attack_session": sid,
                             "split": split, "step": step, "depends_on": []})
    write_json(output / "manifest.json", manifest)
    gt_path = ROOT / "results" / "ground_truth.jsonl"
    for name in CONFIGS:
        directory = output / name
        directory.mkdir()
        print(f"{name}: configure and run {len(manifest)} requests", flush=True)
        write_json(directory / "settings.json", configure(name))
        wait_web(base)
        # Stop the writer before rotation. The next file contains measurement only.
        sql("SELECT pg_rotate_logfile();")
        time.sleep(1)
        log_path = current_log()
        offset = gt_path.stat().st_size if gt_path.exists() else 0
        responses = []
        started = time.perf_counter()
        for item in manifest:
            tick = time.perf_counter()
            status, body = request_json(base + "/login",
                {"username": item["username"], "password": "demo-wrong-password"},
                {"X-Lab-Action": item["action_id"], "X-Lab-Session": item["attack_session"]})
            responses.append({"action_id": item["action_id"], "status": status,
                              "elapsed_ms": (time.perf_counter() - tick) * 1000,
                              "body_bytes": len(body)})
        wall = time.perf_counter() - started
        stats = docker("stats", "--no-stream", "--format", "{{json .}}", "db", "web")
        docker("stop", "web")
        # Change second before rotation so PostgreSQL closes the old file.
        time.sleep(1.1)
        sql("SELECT pg_rotate_logfile();")
        for _ in range(20):
            if current_log() != log_path:
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("Log rotation did not complete; refusing a partial export")
        docker("cp", "db:" + log_path, str(directory / "postgres.jsonl"))
        with gt_path.open("rb") as stream:
            stream.seek(offset)
            (directory / "ground_truth.jsonl").write_bytes(stream.read())
        write_json(directory / "http.json", responses)
        latencies = sorted(row["elapsed_ms"] for row in responses)
        write_json(directory / "cost.json", {"wall_seconds": wall, "requests": len(manifest),
            "requests_per_second": len(manifest) / wall, "container_stats_snapshot": stats,
            "log_bytes": (directory / "postgres.jsonl").stat().st_size,
            "log_bytes_per_request": (directory / "postgres.jsonl").stat().st_size / len(manifest),
            "http_latency_ms_median": statistics.median(latencies),
            "http_latency_ms_p95": latencies[max(0, math.ceil(.95*len(latencies))-1)]})
    from lab.report import build_report
    build_report(output)
    print(f"Artifacts: {output}\nReport: {output / 'rq1.json'}", flush=True)


if __name__ == "__main__":
    main()
