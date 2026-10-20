import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lab import logging as lab_logging
from lab.run import COMMON, CONFIGS


def state(profile="C3"):
    values = {**COMMON, **CONFIGS[profile], "logging_collector": "on",
              "shared_preload_libraries": "pgaudit", "log_destination": "jsonlog",
              "log_timezone": "UTC"}
    return {"server_version_num": 160010, "pgaudit_version": "16.1",
            "current_json_log": "lab_logs/postgresql-old.json", "matching_profiles": [profile],
            "settings": {name: {"value": value, "source": "configuration file", "pending_restart": False}
                         for name, value in values.items()}}


class LogConfigurationTests(unittest.TestCase):
    def test_snapshot_recognizes_c3_and_keeps_effective_setting_sources(self):
        current = state()
        info = {name: current[name] for name in ("server_version_num", "pgaudit_version", "current_json_log")}
        with patch.object(lab_logging, "sql", side_effect=[json.dumps(current["settings"]), json.dumps(info)]):
            result = lab_logging.snapshot()
        self.assertEqual(result["matching_profiles"], ["C3"])
        self.assertEqual(result["compose_file"], "lab/compose.yml")
        self.assertEqual(result["settings"]["pgaudit.log"]["source"], "configuration file")

    def test_preflight_rejects_wrong_version_missing_collector_and_pending_restart(self):
        bad_version = {**state(), "server_version_num": 130023}
        with self.assertRaisesRegex(RuntimeError, "PostgreSQL 16"):
            lab_logging.preflight(bad_version)
        collector_off = state()
        collector_off["settings"]["logging_collector"]["value"] = "off"
        with self.assertRaisesRegex(RuntimeError, "logging_collector=on"):
            lab_logging.preflight(collector_off)
        pending = state()
        pending["settings"]["shared_preload_libraries"]["pending_restart"] = True
        with self.assertRaisesRegex(RuntimeError, "pending restart"):
            lab_logging.preflight(pending)

    def test_status_is_read_only_and_apply_creates_extension_before_profile_change(self):
        with patch.object(lab_logging, "snapshot", return_value=state()), \
                patch.object(lab_logging, "configure") as configure, \
                patch.object(lab_logging, "sql") as sql, \
                patch("sys.argv", ["lab.logging"]), contextlib.redirect_stdout(io.StringIO()):
            lab_logging.main()
            configure.assert_not_called()
            sql.assert_not_called()
        calls = []
        with patch.object(lab_logging, "snapshot", side_effect=[state("C0"), state("C3")]), \
                patch.object(lab_logging, "configure", side_effect=lambda name: calls.append(("configure", name))), \
                patch.object(lab_logging, "sql", side_effect=lambda query: calls.append(("sql", query))), \
                patch("sys.argv", ["lab.logging", "--apply", "C3"]), contextlib.redirect_stdout(io.StringIO()):
            lab_logging.main()
        self.assertEqual(calls, [("sql", "CREATE EXTENSION IF NOT EXISTS pgaudit;"), ("configure", "C3")])

    def test_failed_preflight_does_not_change_database_or_restart_web(self):
        broken = state()
        broken["settings"]["shared_preload_libraries"]["value"] = ""
        with patch.object(lab_logging, "snapshot", return_value=broken), \
                patch.object(lab_logging, "sql") as sql, patch.object(lab_logging, "configure") as configure, \
                patch("sys.argv", ["lab.logging", "--apply", "C3"]):
            with self.assertRaisesRegex(SystemExit, "no settings changed"):
                lab_logging.main()
        sql.assert_not_called()
        configure.assert_not_called()

    def test_export_waits_for_rotation_then_copies_previous_file(self):
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(lab_logging, "current_log", side_effect=["/logs/old.json", "/logs/old.json", "/logs/new.json"]), \
                patch.object(lab_logging.time, "sleep"), patch.object(lab_logging, "sql") as sql, \
                patch.object(lab_logging, "docker") as docker, patch.object(lab_logging, "snapshot", return_value=state()):
            destination = lab_logging.export_log(Path(tmp))
            sql.assert_called_once_with("SELECT pg_rotate_logfile();")
            docker.assert_called_once_with("cp", "db:/logs/old.json", str((destination / "postgres.jsonl").resolve()))
            self.assertEqual(json.loads((destination / "settings.json").read_text())["matching_profiles"], ["C3"])

    def test_export_refuses_to_copy_if_rotation_does_not_complete(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(lab_logging, "current_log", return_value="/logs/old.json"), \
                patch.object(lab_logging.time, "sleep"), patch.object(lab_logging, "sql"), \
                patch.object(lab_logging, "docker") as docker:
            with self.assertRaisesRegex(RuntimeError, "refusing to export an active file"):
                lab_logging.export_log(tmp)
            docker.assert_not_called()
            self.assertEqual(list(Path(tmp).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
