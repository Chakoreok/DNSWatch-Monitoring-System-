from flask import Blueprint, render_template, redirect, url_for, session, make_response
from flask_login import login_required, current_user, logout_user
from services.sniffer import sniffer_service

views_bp = Blueprint('views', __name__)


def _render_auth_page(initial_tab='login'):
    """Shows the Sign In / Create Account page and ends any previous session,
    so the user must authenticate before proceeding to the dashboard."""
    if current_user.is_authenticated:
        logout_user()
    session.clear()
    resp = make_response(render_template('login.html', initial_tab=initial_tab))
    resp.delete_cookie('remember_token')
    # Prevent the browser from showing a cached authenticated page on Back/reopen
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return resp


@views_bp.route('/')
def index():
    """Root URL: the system always starts at Sign In / Create Account."""
    return _render_auth_page('login')

@views_bp.route('/home')
def home():
    return _render_auth_page('login')

@views_bp.route('/landing')
def landing_page():
    """Explicit route for the marketing Landing Page."""
    return render_template('landing.html')

@views_bp.route('/login')
def login_page():
    """Shows the Sign In page."""
    return _render_auth_page('login')

@views_bp.route('/signup')
@views_bp.route('/register')
def signup_page():
    """Shows the Create Account page."""
    return _render_auth_page('signup')

@views_bp.route('/dashboard')
@login_required
def dashboard_page():
    mon_status = sniffer_service.get_status()
    return render_template('dashboard.html', active_page='dashboard', monitoring=mon_status)

@views_bp.route('/website-activity')
@login_required
def website_activity_page():
    mon_status = sniffer_service.get_status()
    return render_template('website_activity.html', active_page='website-activity', monitoring=mon_status)

@views_bp.route('/devices')
@login_required
def devices_page():
    mon_status = sniffer_service.get_status()
    return render_template('devices.html', active_page='devices', monitoring=mon_status)

@views_bp.route('/dns-logs')
@login_required
def dns_logs_page():
    mon_status = sniffer_service.get_status()
    return render_template('dns_logs.html', active_page='dns-logs', monitoring=mon_status)

@views_bp.route('/security-alerts')
@login_required
def security_alerts_page():
    mon_status = sniffer_service.get_status()
    return render_template('security_alerts.html', active_page='security-alerts', monitoring=mon_status)

@views_bp.route('/threat-detection')
@login_required
def threat_detection_page():
    mon_status = sniffer_service.get_status()
    return render_template('threat_detection.html', active_page='threat-detection', monitoring=mon_status)

@views_bp.route('/blocked-dns')
@login_required
def blocked_dns_page():
    mon_status = sniffer_service.get_status()
    return render_template('blocked_dns.html', active_page='blocked-dns', monitoring=mon_status)

@views_bp.route('/reports')
@login_required
def reports_page():
    mon_status = sniffer_service.get_status()
    return render_template('reports.html', active_page='reports', monitoring=mon_status)

@views_bp.route('/settings')
@login_required
def settings_page():
    from database import db
    mon_status = sniffer_service.get_status()
    try:
        url_obj = db.engine.url
        driver = url_obj.drivername or ''
        host = getattr(url_obj, 'host', '') or ''
        port = getattr(url_obj, 'port', '') or ''
        database = getattr(url_obj, 'database', '') or 'dnswatch_db'
        
        if 'sqlite' in driver:
            db_display = f"SQLite ({database})"
        elif 'postgres' in driver:
            db_display = f"PostgreSQL ({host}{f':{port}' if port else ''})"
        else:
            db_display = f"MySQL ({host or '127.0.0.1'}{f':{port}' if port else ':3306'})"
    except Exception:
        db_display = "Active (Connected)"
        database = "dnswatch_db"
        
    return render_template(
        'settings.html',
        active_page='settings',
        monitoring=mon_status,
        db_display=db_display,
        db_name=database
    )
