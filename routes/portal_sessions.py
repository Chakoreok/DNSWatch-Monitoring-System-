"""
routes/portal_sessions.py
=========================
Web Portal Session Tracking API

Tracks every authenticated user's web portal access in real-time.
Used by Admin / Security Analyst panels to see who is currently
viewing the web system, their IP address, browser, pages visited,
and session duration.

Endpoints:
  POST /api/portal-sessions/register    – Register new session on login / page load
  POST /api/portal-sessions/heartbeat   – Keep session alive (ping every 30s)
  POST /api/portal-sessions/page        – Update current page being viewed
  GET  /api/portal-sessions             – List all sessions (Admin / Analyst only)
  GET  /api/portal-sessions/active      – List only ONLINE sessions (Admin / Analyst)
  POST /api/portal-sessions/<id>/end    – Force-end a session (Admin only)
  POST /api/portal-sessions/cleanup     – Mark stale sessions offline (Admin only)
"""

import secrets
import uuid
from flask import Blueprint, request, jsonify, session as flask_session
from flask_login import login_required, current_user
from database import db
from models import WebPortalSession
from datetime import datetime, timedelta

portal_sessions_bp = Blueprint('portal_sessions', __name__)


def _get_client_ip():
    """Extract real client IP, handling proxies / load balancers."""
    for header in ('X-Forwarded-For', 'X-Real-IP', 'CF-Connecting-IP'):
        ip = request.headers.get(header)
        if ip:
            return ip.split(',')[0].strip()
    return request.remote_addr or '0.0.0.0'


def _get_or_create_session_token():
    """Get the portal session token from Flask session, or create a new one."""
    token = flask_session.get('portal_session_token')
    if not token:
        token = secrets.token_hex(32)
        flask_session['portal_session_token'] = token
    return token


# =============================================================================
# POST /api/portal-sessions/register
# Called automatically when any authenticated user loads the app (base.html)
# =============================================================================
@portal_sessions_bp.route('/api/portal-sessions/register', methods=['POST'])
@login_required
def register_session():
    """Create or refresh a portal session record for the current user.
    Also auto-registers the connecting device in the Devices inventory.
    """
    from models import Device
    token = _get_or_create_session_token()
    ip = _get_client_ip()
    ua = request.headers.get('User-Agent', '')
    page = (request.get_json(silent=True) or {}).get('page', '/')

    # --- Parse OS from User-Agent for device_type ---
    if 'Android' in ua:
        os_label = 'Android'
        device_type = 'Web Portal Visitor (Android)'
    elif 'iPhone' in ua or 'iPad' in ua:
        os_label = 'iOS'
        device_type = 'Web Portal Visitor (iOS)'
    elif 'Windows NT' in ua:
        os_label = 'Windows'
        device_type = 'Web Portal Visitor (Windows)'
    elif 'Mac OS X' in ua:
        os_label = 'macOS'
        device_type = 'Web Portal Visitor (macOS)'
    elif 'Linux' in ua:
        os_label = 'Linux'
        device_type = 'Web Portal Visitor (Linux)'
    else:
        os_label = 'Unknown'
        device_type = 'Web Portal Visitor'

    # --- Upsert portal session record ---
    existing = WebPortalSession.query.filter_by(session_token=token).first()
    if existing:
        existing.ip_address = ip
        existing.user_agent = ua
        existing.current_page = page
        existing.last_heartbeat = datetime.utcnow()
        existing.is_active = True
    else:
        existing = WebPortalSession(
            session_token=token,
            user_id=current_user.id,
            username=current_user.username,
            role_name=current_user.role.name if current_user.role else 'Viewer',
            ip_address=ip,
            user_agent=ua,
            current_page=page,
            started_at=datetime.utcnow(),
            last_heartbeat=datetime.utcnow(),
            is_active=True
        )
        db.session.add(existing)

    # --- Auto-register device in Devices inventory ---
    try:
        device_name = f"Portal-{current_user.username} ({os_label})"
        dev = Device.query.filter_by(client_ip=ip).first()
        if not dev:
            dev = Device(
                client_ip=ip,
                mac_address='-',
                device_name=device_name,
                device_type=device_type,
                dns_queries=0,
                last_seen=datetime.utcnow(),
                status='Active'
            )
            db.session.add(dev)
        else:
            # Update last seen + device name/type to reflect portal visitor status
            dev.last_seen = datetime.utcnow()
            dev.status = 'Active'
            # Only update name/type if it hasn't been customized away from portal naming
            if 'Portal' not in dev.device_name:
                dev.device_name = device_name
            if 'Portal' not in dev.device_type:
                dev.device_type = device_type
    except Exception as dev_err:
        # Don't fail session registration if device upsert fails
        print(f'[Portal] Device auto-register warning: {dev_err}')

    db.session.commit()
    return jsonify({'success': True, 'token': token})



# =============================================================================
# POST /api/portal-sessions/heartbeat
# Called every 30 seconds to keep the session marked as online
# =============================================================================
@portal_sessions_bp.route('/api/portal-sessions/heartbeat', methods=['POST'])
@login_required
def heartbeat():
    """Update last_heartbeat to signal the user is still online."""
    token = flask_session.get('portal_session_token')
    if not token:
        return jsonify({'success': False, 'message': 'No session token.'}), 400

    data = request.get_json(silent=True) or {}
    session_obj = WebPortalSession.query.filter_by(session_token=token).first()
    if session_obj:
        session_obj.last_heartbeat = datetime.utcnow()
        if data.get('page'):
            session_obj.current_page = data['page']
        db.session.commit()

    return jsonify({'success': True})


# =============================================================================
# POST /api/portal-sessions/page
# Called when the user navigates to a new page
# =============================================================================
@portal_sessions_bp.route('/api/portal-sessions/page', methods=['POST'])
@login_required
def update_page():
    """Update the current page being viewed by the user."""
    token = flask_session.get('portal_session_token')
    if not token:
        return jsonify({'success': False}), 400

    data = request.get_json(silent=True) or {}
    page = data.get('page', '/')

    session_obj = WebPortalSession.query.filter_by(session_token=token).first()
    if session_obj:
        session_obj.current_page = page
        session_obj.last_heartbeat = datetime.utcnow()
        db.session.commit()

    return jsonify({'success': True})


# =============================================================================
# GET /api/portal-sessions
# Returns all portal sessions (Admin / Analyst only)
# =============================================================================
@portal_sessions_bp.route('/api/portal-sessions', methods=['GET'])
@login_required
def list_sessions():
    """List all web portal sessions. Requires Admin or Analyst role."""
    if not (current_user.is_admin or current_user.is_analyst):
        return jsonify({'success': False, 'message': 'Access denied.'}), 403

    # Auto-mark stale sessions (no heartbeat in 3 minutes) as offline
    stale_cutoff = datetime.utcnow() - timedelta(minutes=3)
    WebPortalSession.query.filter(
        WebPortalSession.last_heartbeat < stale_cutoff,
        WebPortalSession.is_active == True
    ).update({'is_active': False})
    db.session.commit()

    only_active = request.args.get('active', 'false').lower() == 'true'
    role_filter = request.args.get('role', '').strip()

    query = WebPortalSession.query
    if only_active:
        query = query.filter_by(is_active=True)
    if role_filter:
        query = query.filter(WebPortalSession.role_name.ilike(f'%{role_filter}%'))

    sessions = query.order_by(WebPortalSession.last_heartbeat.desc()).limit(200).all()

    # Count online (heartbeat within last 2 min)
    cutoff_2m = datetime.utcnow() - timedelta(minutes=2)
    online_count = WebPortalSession.query.filter(
        WebPortalSession.last_heartbeat >= cutoff_2m,
        WebPortalSession.is_active == True
    ).count()

    return jsonify({
        'success': True,
        'sessions': [s.to_dict() for s in sessions],
        'total': len(sessions),
        'online_count': online_count
    })


# =============================================================================
# GET /api/portal-sessions/active
# Returns only currently-online sessions
# =============================================================================
@portal_sessions_bp.route('/api/portal-sessions/active', methods=['GET'])
@login_required
def active_sessions():
    """Returns only sessions with recent heartbeat (within 2 min)."""
    if not (current_user.is_admin or current_user.is_analyst):
        return jsonify({'success': False, 'message': 'Access denied.'}), 403

    cutoff = datetime.utcnow() - timedelta(minutes=2)
    sessions = WebPortalSession.query.filter(
        WebPortalSession.last_heartbeat >= cutoff,
        WebPortalSession.is_active == True
    ).order_by(WebPortalSession.last_heartbeat.desc()).all()

    return jsonify({
        'success': True,
        'sessions': [s.to_dict() for s in sessions],
        'online_count': len(sessions)
    })


# =============================================================================
# POST /api/portal-sessions/<id>/end
# Force-terminate a specific session (Admin only)
# =============================================================================
@portal_sessions_bp.route('/api/portal-sessions/<int:session_id>/end', methods=['POST'])
@login_required
def end_session(session_id):
    """Force-end a specific portal session. Admin only."""
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Only administrators can terminate sessions.'}), 403

    session_obj = WebPortalSession.query.get(session_id)
    if not session_obj:
        return jsonify({'success': False, 'message': 'Session not found.'}), 404

    session_obj.is_active = False
    db.session.commit()
    return jsonify({'success': True, 'message': f'Session for {session_obj.username} has been terminated.'})


# =============================================================================
# POST /api/portal-sessions/cleanup
# Remove old/stale session records older than 24 hours (Admin only)
# =============================================================================
@portal_sessions_bp.route('/api/portal-sessions/cleanup', methods=['POST'])
@login_required
def cleanup_sessions():
    """Delete portal session records older than 24 hours. Admin only."""
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied.'}), 403

    cutoff = datetime.utcnow() - timedelta(hours=24)
    deleted = WebPortalSession.query.filter(
        WebPortalSession.started_at < cutoff,
        WebPortalSession.is_active == False
    ).delete()
    db.session.commit()

    return jsonify({'success': True, 'message': f'{deleted} stale session(s) removed.'})
