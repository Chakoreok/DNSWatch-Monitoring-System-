from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

_schema_ok = False


def ensure_schema():
    """Adds columns introduced after the initial deploy. db.create_all() only
    creates missing tables; it never alters existing ones.

    Safe to call repeatedly: after the first success it is a no-op. Callers that
    need the new columns call it lazily, so a failed attempt at startup (e.g. the
    database briefly hitting its connection limit during a redeploy) heals itself
    on the next request. Must be called inside an app context.

    Returns (ok: bool, error_message: str).
    """
    global _schema_ok
    if _schema_ok:
        return True, ''
    from sqlalchemy import inspect, text
    try:
        cols = {c['name'] for c in inspect(db.engine).get_columns('monitoring_sessions')}
        if 'last_heartbeat' not in cols:
            with db.engine.begin() as conn:
                conn.execute(text("ALTER TABLE monitoring_sessions ADD COLUMN last_heartbeat DATETIME NULL"))
            print("[DNSWatch] Added monitoring_sessions.last_heartbeat column.")
        _schema_ok = True
        return True, ''
    except Exception as e:
        print(f"[DNSWatch] Schema migration failed: {e}")
        return False, str(e)
