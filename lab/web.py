"""Launch the existing app with lab-only, independent query instrumentation.

The SQL, driver, pool, and execute_query transaction behavior are retained.
HTTP scenario IDs are written ONLY to the ground truth, never to PostgreSQL.
"""
import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from flask import has_request_context, request

import database

LOCK = threading.Lock()


def now():
    return datetime.now(timezone.utc).isoformat()


def execute_query(query, params=None, fetch=True):
    conn = database.get_connection()
    action = request.headers.get("X-Lab-Action") if has_request_context() else None
    record = {
        "action_id": action,
        "attack_session": request.headers.get("X-Lab-Session") if action else None,
        "started_at": now(),
        "pid": conn.get_backend_pid(),
        "sql": query,
        "parameters": params,
    }
    started = time.perf_counter()
    try:
        with conn.cursor() as cursor:
            cursor.execute(query, params)
            record.update(outcome="success", sqlstate="00000", rowcount=cursor.rowcount)
            result = cursor.fetchall() if fetch else None
            if query.strip().upper().startswith(("INSERT", "UPDATE", "DELETE")):
                conn.commit()
            return result
    except Exception as exc:
        record.update(outcome="error", sqlstate=getattr(exc, "pgcode", None))
        conn.rollback()
        raise
    finally:
        record.update(ended_at=now(), elapsed_ms=(time.perf_counter() - started) * 1000)
        try:
            if action:
                path = Path(os.environ["LAB_GROUND_TRUTH"])
                with LOCK, path.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(record, default=str) + "\n")
        finally:
            database.return_connection(conn)


def main():
    # Patch before app imports this function, including its dependent modules.
    database.execute_query = execute_query
    from app import app

    database.init_db()
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
