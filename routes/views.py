from flask import Blueprint, render_template, redirect, url_for
from flask_login import login_required, current_user
from services.sniffer import sniffer_service

views_bp = Blueprint('views', __name__)

@views_bp.route('/')
def index():
    """Root URL redirects to dashboard if authenticated, or login page if unauthenticated."""
    if current_user.is_authenticated:
        return redirect(url_for('views.dashboard_page'))
    return redirect(url_for('views.login_page'))

@views_bp.route('/home')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('views.dashboard_page'))
    return redirect(url_for('views.login_page'))

@views_bp.route('/login')
def login_page():
    """Shows Login page, or redirects to dashboard if already authenticated."""
    if current_user.is_authenticated:
        return redirect(url_for('views.dashboard_page'))
    return render_template('login.html')

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

@views_bp.route('/reports')
@login_required
def reports_page():
    mon_status = sniffer_service.get_status()
    return render_template('reports.html', active_page='reports', monitoring=mon_status)

@views_bp.route('/settings')
@login_required
def settings_page():
    mon_status = sniffer_service.get_status()
    return render_template('settings.html', active_page='settings', monitoring=mon_status)
