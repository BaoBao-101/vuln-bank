import contextlib
import io
import importlib.util
import json
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from lab import benchmark, report
from lab.scenarios import actions


def raw(sql, **extra):
    return {"timestamp": "2026-01-01 00:00:01.000 UTC", "pid": 42,
            "session_id": "backend-a", "user": "postgres", "remote_host": "172.20.0.2",
            "dbname": "vulnerable_bank", "message": "statement: " + sql, **extra}


class LogTests(unittest.TestCase):
    def test_nested_csv_preserves_commas_quotes_and_newlines(self):
        sql = 'SELECT \'a,b\', \'a"b\'\nFROM users'
        stream = io.StringIO()
        import csv
        csv.writer(stream).writerow(["SESSION", "1", "1", "READ", "SELECT", "", "", sql, "<none>"])
        event = report.parse_event(raw(sql, message="AUDIT: " + stream.getvalue().strip()))
        self.assertEqual(event["sql"], sql)
        self.assertIsNone(event["outcome"])
        self.assertIsNone(event["parameters"])

    def test_error_query_is_recovered_and_not_mistaken_for_success(self):
        event = report.parse_event(raw("", message="division by zero", statement="SELECT 1/0",
                                       error_severity="ERROR", state_code="22012"))
        self.assertEqual(event["sql"], "SELECT 1/0")
        self.assertEqual(event["outcome"], "error")

    def test_exact_match_uses_pid_time_and_preserves_sql_literals(self):
        truth = [{"action_id": "a", "pid": 42, "sql": "SELECT 'a  b'",
                  "started_at": "2026-01-01T00:00:00.999900+00:00",
                  "ended_at": "2026-01-01T00:00:01.100000+00:00"}]
        events = [report.parse_event(raw("SELECT 'a  b'")),
                  report.parse_event(raw("SELECT 'a b'")),
                  report.parse_event(raw("SELECT 'a  b'", pid=43)),
                  report.parse_event(raw("SELECT 'a  b'", timestamp="2026-01-01 00:01:01.000 UTC"))]
        self.assertEqual(len(report.match_events(truth, events)["a"]), 1)

    def test_pairwise_penalizes_merges_and_missing_queries(self):
        merged = report.pairwise_scores(["a", "a", "b", "b"], ["x"]*4)
        self.assertAlmostEqual(merged["precision"], 1/3)
        self.assertEqual(merged["recall"], 1)
        missing = report.pairwise_scores(["a", "a", "b", "b"], ["x", "x", None, None])
        self.assertEqual(missing["recall"], .5)
        self.assertEqual(missing["precision"], 1)

    def test_time_threshold_uses_only_observed_properties(self):
        items = {"a": report.parse_event(raw("SELECT 1")),
                 "b": report.parse_event(raw("SELECT 2", timestamp="2026-01-01 00:03:00.000 UTC"))}
        one = report.reconstruct(items, 1, "user_ip_database")
        five = report.reconstruct(items, 5, "user_ip_database")
        self.assertNotEqual(one["a"], one["b"])
        self.assertEqual(five["a"], five["b"])


class BenchmarkTests(unittest.TestCase):
    def test_classifier_inputs_exclude_gold_and_session_identifiers(self):
        current = benchmark.public_query({"id": "q1", "sql": "SELECT 1", "outcome": None,
            "gold_label": "normal", "gold_session": "secret", "family": "held-out", "split": "novel"})
        self.assertEqual(set(current), {"id", "sql", "outcome"})

    def test_format_validation_rejects_nonstring_label_and_string_evidence(self):
        self.assertFalse(benchmark.validate({"label": [], "evidence_ids": [], "reason": ""}))
        self.assertFalse(benchmark.validate({"label": "normal", "evidence_ids": "q1", "reason": ""}))

    def test_wrong_and_missing_labels_reduce_f1_and_evidence(self):
        rows = [dict(gold_label="normal", label="normal", gold_evidence=["q1"], evidence_ids=["fake"],
                     invalid=False, invented_ids=["fake"], outside_window_ids=[], elapsed_ms=1),
                dict(gold_label="recon", label="MISSING", gold_evidence=["q2"], evidence_ids=[],
                     invalid=False, invented_ids=[], outside_window_ids=[], elapsed_ms=0)]
        values = benchmark.score(rows, ["normal", "recon"])
        self.assertEqual(values["macro_f1"], .5)
        self.assertEqual(values["evidence_f1_macro"], 0)
        self.assertEqual(values["nonexistent_evidence_response_rate"], .5)

    def test_bootstrap_reproducible_and_requires_multiple_sessions(self):
        row = dict(gold_label="normal", label="normal", gold_evidence=["q1"], evidence_ids=["q1"],
                   invalid=False, invented_ids=[], outside_window_ids=[], elapsed_ms=1, gold_session="a")
        rows = [row, {**row, "gold_session": "b"}]
        result = benchmark.bootstrap_delta(rows, rows, ["normal"], repetitions=30)
        self.assertEqual(result["macro_f1"]["bootstrap_95"], [0, 0])
        self.assertFalse(benchmark.bootstrap_delta([row], rows, ["normal"])["available"])

    def test_full_report_to_rule_benchmark_with_missing_and_duplicate_logs(self):
        # Synthetic fixture verifies bookkeeping; these are never presented as lab measurements.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest, truth = [], []
            for split in ("dev", "known", "novel"):
                for session in range(2):
                    for i, spec in enumerate(actions(session, split)[:3]):
                        aid = f"{split}-{session}-{i}"
                        manifest.append({**spec, "action_id": aid, "attack_session": f"{split}-{session}",
                                         "split": split, "depends_on": []})
                        username = spec["username"]
                        truth.append({"action_id": aid, "attack_session": f"{split}-{session}", "pid": 42,
                            "sql": f"SELECT * FROM users WHERE username='{username}' AND password='x'",
                            "started_at": "2026-01-01T00:00:00.999+00:00",
                            "ended_at": "2026-01-01T00:00:01.100+00:00", "parameters": None})
            (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            for name in ("C0", "C1", "C2", "C3"):
                target = root / name
                target.mkdir()
                (target / "ground_truth.jsonl").write_text("\n".join(map(json.dumps, truth)), encoding="utf-8")
                # Missing all events in C0; duplicates elsewhere must not inflate recall.
                logs = [] if name == "C0" else [raw(t["sql"]) for t in truth for _ in range(2)]
                (target / "postgres.jsonl").write_text("\n".join(map(json.dumps, logs)), encoding="utf-8")
                (target / "cost.json").write_text(json.dumps({"log_bytes": len(logs)*100}), encoding="utf-8")
            result = report.build_report(root)
            self.assertEqual(result["configs"]["C0"]["recall_by_group"]["auth_bypass"]["recall"], 0)
            self.assertEqual(result["configs"]["C1"]["recall_by_group"]["auth_bypass"]["recall"], 1)
            self.assertIsNone(result["configs"]["C1"]["attributes"]["parameters"]["rate"])
            completed = subprocess.run([sys.executable, "-m", "lab.benchmark", str(root / "C1"),
                                        "--windows", "0", "2"], capture_output=True, text=True)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            metrics = json.loads((root / "C1" / "benchmark" / "metrics.json").read_text())
            self.assertIn("rule-k0", metrics)
            self.assertEqual(metrics["rule-k0"]["observed_only"]["n"], 12)


class InstrumentationTests(unittest.TestCase):
    def test_ground_truth_is_independent_and_pool_connection_is_returned_on_error(self):
        class Cursor:
            rowcount = 1
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def execute(self, sql, params):
                self.executed = (sql, params)
                if sql == "SELECT 1/0":
                    exc = ValueError("division by zero")
                    exc.pgcode = "22012"
                    raise exc
            def fetchall(self):
                return [(1,)]
        class Connection:
            def __init__(self):
                self.c = Cursor()
                self.rollbacks = 0
            def cursor(self):
                return self.c
            def get_backend_pid(self):
                return 42
            def rollback(self):
                self.rollbacks += 1
        conn, returned = Connection(), []
        fake_db = types.ModuleType("database")
        fake_db.get_connection = lambda: conn
        fake_db.return_connection = returned.append
        fake_flask = types.ModuleType("flask")
        fake_flask.has_request_context = lambda: True
        fake_flask.request = types.SimpleNamespace(headers={"X-Lab-Action": "secret-action",
                                                           "X-Lab-Session": "secret-session"})
        with tempfile.TemporaryDirectory() as tmp, patch.dict(sys.modules, {"database": fake_db, "flask": fake_flask}):
            filename = Path(tmp) / "truth.jsonl"
            spec = importlib.util.spec_from_file_location("isolated_lab_web", Path(__file__).resolve().parents[1] / "lab" / "web.py")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            with patch.dict("os.environ", {"LAB_GROUND_TRUTH": str(filename)}):
                self.assertEqual(module.execute_query("SELECT 1"), [(1,)])
                self.assertEqual(conn.c.executed, ("SELECT 1", None))
                with self.assertRaisesRegex(ValueError, "division by zero"):
                    module.execute_query("SELECT 1/0")
            records = report.load_lines(filename)
            self.assertEqual([r["outcome"] for r in records], ["success", "error"])
            self.assertEqual(records[1]["sqlstate"], "22012")
            self.assertEqual(records[0]["attack_session"], "secret-session")
            self.assertEqual(conn.rollbacks, 1)
            self.assertEqual(returned, [conn, conn])


if __name__ == "__main__":
    unittest.main()
