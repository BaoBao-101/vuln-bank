"""Parse PostgreSQL JSON + nested pgAudit CSV and score RQ1.

Ground truth is used to score matches, never to infer reconstructed sessions.
Strict matching: same backend PID, exact stripped SQL, execution time interval.
"""
import argparse
import csv
import io
import json
import math
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path


def load_lines(path):
    with Path(path).open(encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def timestamp(value):
    return datetime.fromisoformat(value.replace(" UTC", "+00:00").replace("Z", "+00:00")).timestamp()


def parse_event(raw):
    message = raw.get("message", "")
    sql = None
    source = None
    parameters = None
    if message.startswith("AUDIT: "):
        fields = next(csv.reader(io.StringIO(message[7:])))
        if len(fields) < 9:
            raise ValueError("Malformed pgAudit CSV record")
        sql, source = fields[7], "pgaudit"
        parameters = fields[8] if fields[8] not in ("<not logged>", "<none>") else None
    elif message.startswith("statement: "):
        sql, source = message[len("statement: "):], "native"
    elif raw.get("statement") and raw.get("error_severity") in ("ERROR", "FATAL", "PANIC"):
        sql, source = raw["statement"], "error"
    if not sql:
        return None
    return {
        "timestamp": raw["timestamp"], "pid": raw.get("pid"),
        "db_session": raw.get("session_id"), "user": raw.get("user"),
        "ip": raw.get("remote_host"), "database": raw.get("dbname"),
        "sql": sql.strip(), "outcome": "error" if source == "error" else None,
        "sqlstate": raw.get("state_code") if source == "error" else None,
        "parameters": parameters, "source": source,
    }


def match_events(truth, events):
    index = defaultdict(list)
    for event in events:
        index[(event["pid"], event["sql"])].append(event)
    matches = {}
    for item in truth:
        start, end = timestamp(item["started_at"]), timestamp(item["ended_at"])
        candidates = [event for event in index[(item["pid"], item["sql"].strip())]
                      if start - 0.002 <= timestamp(event["timestamp"]) <= end + 0.002]
        matches[item["action_id"]] = sorted(candidates, key=lambda e: timestamp(e["timestamp"]))
    return matches


def choose2(n):
    return n * (n - 1) // 2


def pairwise_scores(truth_groups, predicted_groups):
    """None predictions represent missing observations, not a shared cluster."""
    actual = Counter(truth_groups)
    predicted = Counter(p for p in predicted_groups if p is not None)
    joint = Counter((a, p) for a, p in zip(truth_groups, predicted_groups) if p is not None)
    tp = sum(choose2(n) for n in joint.values())
    true_pairs = sum(choose2(n) for n in actual.values())
    predicted_pairs = sum(choose2(n) for n in predicted.values())
    precision = tp / predicted_pairs if predicted_pairs else None
    recall = tp / true_pairs if true_pairs else None
    f1 = 2 * tp / (predicted_pairs + true_pairs) if predicted_pairs + true_pairs else None
    return dict(precision=precision, recall=recall, f1=f1, true_pairs=true_pairs,
                predicted_pairs=predicted_pairs, true_positive_pairs=tp)


def wilson_lower(hits, total):
    if not total:
        return None
    z = 1.959963984540054
    p = hits / total
    return (p + z*z/(2*total) - z * math.sqrt(p*(1-p)/total + z*z/(4*total*total))) / (1+z*z/total)


def reconstruct(events, minutes, strategy):
    assignments, last, numbers = {}, {}, Counter()
    for action_id, item in sorted(events.items(), key=lambda pair: timestamp(pair[1]["timestamp"])):
        key = (item.get("db_session"),) if strategy == "db_connection" else (
            item.get("user"), item.get("ip"), item.get("database"))
        instant = timestamp(item["timestamp"])
        if key not in last or instant - last[key] > minutes * 60:
            numbers[key] += 1
        last[key] = instant
        assignments[action_id] = str((key, numbers[key]))
    return assignments


def build_report(directory):
    directory = Path(directory)
    manifest = {item["action_id"]: item for item in json.loads((directory / "manifest.json").read_text(encoding="utf-8"))}
    all_reports = {}
    for config in ("C0", "C1", "C2", "C3"):
        target = directory / config
        truth = load_lines(target / "ground_truth.jsonl")
        counts = Counter(item["action_id"] for item in truth)
        if set(counts) != set(manifest) or any(count != 1 for count in counts.values()):
            raise ValueError(f"{config}: missing/duplicate ground truth; refusing misleading metrics")
        events = [event for raw in load_lines(target / "postgres.jsonl") if (event := parse_event(raw))]
        with (target / "parsed.jsonl").open("w", encoding="utf-8") as stream:
            for event in events:
                stream.write(json.dumps(event) + "\n")
        matches = match_events(truth, events)
        observations = {}
        for action_id, values in matches.items():
            if values:
                merged = dict(values[0])
                for field in ("user", "ip", "database", "outcome", "sqlstate", "parameters"):
                    merged[field] = next((e[field] for e in values if e.get(field) is not None), None)
                observations[action_id] = merged
        groups = defaultdict(list)
        for item in truth:
            groups[manifest[item["action_id"]]["group"]].append(item)
        recall = {}
        for group, items in sorted(groups.items()):
            hits = sum(bool(matches[item["action_id"]]) for item in items)
            n = len(items)
            recall[group] = {"actions": n, "recorded": hits, "recall": hits/n,
                             "miss_pct": 100*(n-hits)/n, "wilson_lower_95": wilson_lower(hits, n)}
        attrs = {}
        for field in ("user", "ip", "database", "sql", "outcome", "parameters"):
            applicable = [item for item in truth if field != "parameters" or item.get("parameters")]
            n = len(applicable)
            hits = sum(observations.get(item["action_id"], {}).get(field) is not None for item in applicable)
            attrs[field] = {"applicable": n, "filled": hits, "rate": hits/n if n else None}
        sessions = []
        test_truth = [item for item in truth if manifest[item["action_id"]]["split"] != "dev"]
        for strategy in ("db_connection", "user_ip_database"):
            for minutes in (1, 5, 15, 30):
                assignments = reconstruct(observations, minutes, strategy)
                actual = [item["attack_session"] for item in test_truth]
                predicted = [assignments.get(item["action_id"]) for item in test_truth]
                observed = [(a, p) for a, p in zip(actual, predicted) if p is not None]
                sessions.append({"strategy": strategy, "idle_minutes": minutes,
                    "end_to_end": pairwise_scores(actual, predicted),
                    "observed_only": pairwise_scores([a for a, p in observed], [p for a, p in observed])})
        # Anonymous IDs and predicted sessions are the only IDs exposed to classifiers.
        id_map = {item["action_id"]: f"q{i:05d}" for i, item in enumerate(truth)}
        assignments = reconstruct(observations, 5, "user_ip_database")
        dataset = []
        for item in truth:
            aid = item["action_id"]
            spec = manifest[aid]
            obs = observations.get(aid)
            dataset.append({"id": id_map[aid], "observed": obs is not None,
                "sql": obs["sql"] if obs else None, "timestamp": obs["timestamp"] if obs else None,
                "outcome": obs.get("outcome") if obs else None,
                "predicted_session": assignments.get(aid),
                "gold_session": item["attack_session"], "gold_label": spec["label"],
                "gold_evidence": [id_map[aid]] + [id_map[d] for d in spec["depends_on"]],
                "family": spec["family"], "split": spec["split"]})
        (target / "dataset.json").write_text(json.dumps(dataset, indent=2), encoding="utf-8")
        attack_groups = [value for key, value in recall.items() if key != "benign"]
        all_reports[config] = {"recall_by_group": recall, "attributes": attrs,
            "session_reconstruction": sessions,
            "passes_point_recall_095": all(group["recall"] >= .95 for group in attack_groups),
            "passes_wilson_lower_095": all(group["wilson_lower_95"] >= .95 for group in attack_groups),
            "cost": json.loads((target / "cost.json").read_text(encoding="utf-8"))}
    eligible = [name for name, report in all_reports.items() if report["passes_point_recall_095"]]
    recommended = min(eligible, key=lambda name: all_reports[name]["cost"]["log_bytes"]) if eligible else None
    result = {"configs": all_reports,
        "smallest_log_config_passing_point_recall": recommended,
        "selection_scope": "Pilot by log bytes and point recall only; not a claim of sufficient context or lowest CPU cost.",
        "limitations": ["An action is one client query batch, including stacked SQL.",
            "Exact-SQL matching is conservative; partial/deparsed statements can be counted as missed.",
            "PostgreSQL sees the web server IP, not the attacker's HTTP IP.",
            "Only failed queries have an explicit outcome in this parser; no success is inferred from audit lines.",
            "This suite has no bind parameters and all session gaps are short.",
            "Wilson intervals are descriptive; actions in a session are not independent.",
            "Cost includes control queries/health checks; stats are snapshots, not peak resource measurements."]}
    (directory / "rq1.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    with (directory / "rq1.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(["config", "group", "actions", "recorded", "recall", "miss_pct", "wilson_lower_95", "log_bytes"])
        for name, report in all_reports.items():
            for group, values in report["recall_by_group"].items():
                writer.writerow([name, group, *[values[key] for key in
                    ("actions", "recorded", "recall", "miss_pct", "wilson_lower_95")], report["cost"]["log_bytes"]])
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_directory", type=Path)
    build_report(parser.parse_args().run_directory)
