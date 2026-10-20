import contextlib
import io
import unittest
from unittest.mock import call, patch

from lab import run


class ResourceStatsTests(unittest.TestCase):
    def test_queries_one_service_at_a_time(self):
        def compose_stats(*args):
            self.assertEqual(args[:4], ("stats", "--no-stream", "--format", "{{json .}}"))
            self.assertEqual(len(args), 5)
            return '{"Name":"' + args[4] + '"}\n'
        with patch.object(run, "docker", side_effect=compose_stats) as docker:
            snapshot, errors = run.collect_stats()
        self.assertEqual(snapshot, '{"Name":"db"}\n{"Name":"web"}')
        self.assertEqual(errors, {})
        self.assertEqual(docker.call_count, 2)

    def test_stats_failure_preserves_other_service_and_records_error(self):
        with patch.object(run, "docker", side_effect=[RuntimeError("stats unsupported"), '{"Name":"web"}']), \
                contextlib.redirect_stdout(io.StringIO()):
            snapshot, errors = run.collect_stats()
        self.assertEqual(snapshot, '{"Name":"web"}')
        self.assertEqual(errors, {"db": "stats unsupported"})

    def test_unavailable_stats_do_not_abort_the_measurement(self):
        with patch.object(run, "docker", side_effect=OSError("stats unavailable")), \
                contextlib.redirect_stdout(io.StringIO()):
            snapshot, errors = run.collect_stats()
        self.assertEqual(snapshot, "")
        self.assertEqual(set(errors), {"db", "web"})


if __name__ == "__main__":
    unittest.main()
