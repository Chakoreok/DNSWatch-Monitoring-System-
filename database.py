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
        # Create any newly defined tables (threat_feeds, domain_whitelist)
        db.create_all()
        
        inspector = inspect(db.engine)
        # 1. Check monitoring_sessions.last_heartbeat
        session_cols = {c['name'] for c in inspector.get_columns('monitoring_sessions')}
        if 'last_heartbeat' not in session_cols:
            with db.engine.begin() as conn:
                conn.execute(text("ALTER TABLE monitoring_sessions ADD COLUMN last_heartbeat DATETIME NULL"))
            print("[DNSWatch] Added monitoring_sessions.last_heartbeat column.")
            
        # 2. Check malicious_domains.feed_source
        mal_cols = {c['name'] for c in inspector.get_columns('malicious_domains')}
        if 'feed_source' not in mal_cols:
            with db.engine.begin() as conn:
                conn.execute(text("ALTER TABLE malicious_domains ADD COLUMN feed_source VARCHAR(100) NULL DEFAULT 'Manual'"))
            print("[DNSWatch] Added malicious_domains.feed_source column.")
            
        _schema_ok = True
        return True, ''
    except Exception as e:
        print(f"[DNSWatch] Schema migration failed: {e}")
        return False, str(e)
