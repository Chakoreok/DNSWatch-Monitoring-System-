import os
from flask import Flask
from flask_login import LoginManager
from config import Config
from database import db, ensure_schema
from models import User
from services.sniffer import sniffer_service
from services.detection_engine import detection_engine
from services.dns_sinkhole import dns_sinkhole_service

def seed_defaults():
    """Seeds default roles, users, and rules on first deploy if database is empty."""
    from models import Role, User, FrequencyRuleConfig, MaliciousDomain, DetectionRule
    
    # 1. Roles
    roles_data = [
        ("Administrator", "Full system administrator access"),
        ("Security Analyst", "Monitor real-time activity and investigate alerts"),
        ("Viewer", "Read-only dashboard access")
    ]
    for name, desc in roles_data:
        if not Role.query.filter_by(name=name).first():
            db.session.add(Role(name=name, description=desc))
    db.session.commit()
    
    admin_role = Role.query.filter_by(name="Administrator").first()
    analyst_role = Role.query.filter_by(name="Security Analyst").first()
    viewer_role = Role.query.filter_by(name="Viewer").first()
    
    # 2. Users
    users_data = [
        ("admin", "admin@dnswatch.local", "admin123", admin_role.id if admin_role else 1, "Administrator", "ACTIVE"),
        ("analyst", "analyst@dnswatch.local", "analyst123", analyst_role.id if analyst_role else 2, "Security Analyst", "ACTIVE"),
        ("viewer", "viewer@dnswatch.local", "viewer123", viewer_role.id if viewer_role else 3, "System Viewer", "ACTIVE")
    ]
    for username, email, pwd, role_id, full_name, status in users_data:
        u = User.query.filter_by(username=username).first()
        if not u:
            u = User(username=username, email=email, role_id=role_id, full_name=full_name, status=status)
            u.set_password(pwd)
            db.session.add(u)
    db.session.commit()
    
    # 3. Frequency Config
    if not FrequencyRuleConfig.query.first():
        db.session.add(FrequencyRuleConfig(
            threshold=Config.DEFAULT_FREQUENCY_THRESHOLD,
            time_window=Config.DEFAULT_FREQUENCY_WINDOW,
            action="Alert",
            status="Active"
        ))
        db.session.commit()
        
    # 4. Malicious Domains
    if not MaliciousDomain.query.first():
        seed_malicious_domains = [
            ("malicious-site.net", "Malware / Phishing", "HIGH", "Known malicious domain delivering trojans", "Active", "admin"),
            ("phishing-alert.com", "Phishing", "HIGH", "Credential harvesting login portal", "Active", "admin"),
            ("bad-downloads.com", "Malware Distribution", "HIGH", "Hosts malicious executable payloads", "Active", "admin"),
            ("tracker.badsite.org", "Spyware / Tracker", "MEDIUM", "Telemetry tracker and ad injection", "Active", "admin"),
            ("malware-hosting.net", "C2 Infrastructure", "HIGH", "Command and Control server", "Active", "admin"),
            ("suspicious-domain.xyz", "Phishing", "MEDIUM", "Newly registered suspicious domain", "Active", "admin")
        ]
        for domain, cat, sev, desc, stat, added_by in seed_malicious_domains:
            db.session.add(MaliciousDomain(
                domain=domain, category=cat, severity=sev, description=desc, status=stat, added_by=added_by
            ))
        db.session.commit()
        
    # 5. Detection Rules
    if not DetectionRule.query.first():
        seed_rules = [
            ("Phishing Keywords Pattern", "KEYWORD", "login-verify, account-update, secure-banking, auth-portal, wallet-connect, verify-account", "Phishing / Social Engineering", "MEDIUM", "Alert", "Flags domains containing high-risk compound phishing patterns (e.g. login-verify, account-update)"),
            ("Suspicious TLDs", "TLD_BLACKLIST", ".xyz, .top, .club, .online, .info, .tk, .ml, .ga, .cf, .gq", "Suspicious Pattern", "MEDIUM", "Alert", "Flags domains using top-level domains commonly abused in malware campaigns"),
            ("Blocked IP in Domain", "PATTERN", "@*", "DNS Spoofing / Malformed", "HIGH", "Block", "Blocks queries formatted with suspicious embedded IP patterns or symbols")
        ]
        for name, rtype, pattern, cat, sev, action, desc in seed_rules:
            db.session.add(DetectionRule(
                rule_name=name, rule_type=rtype, pattern=pattern, category=cat, severity=sev, action=action, description=desc, is_active=True
            ))
        db.session.commit()
        
    # 6. Threat Intelligence Feeds
    from services.threat_feed_service import threat_feed_service
    threat_feed_service.init_default_feeds()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Apply ProxyFix for correct protocol/host resolution behind Render reverse proxy
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    # Initialize Database
    db.init_app(app)
    
    # Initialize Flask-Login
    login_manager = LoginManager()
    login_manager.login_view = 'views.login_page'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.init_app(app)
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # CORS & Preflight handling
    @app.before_request
    def handle_cors_preflight():
        from flask import request, Response
        if request.method == 'OPTIONS':
            res = Response()
            res.headers['Access-Control-Allow-Origin'] = '*'
            res.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization,X-Sensor-Key,X-Requested-With'
            res.headers['Access-Control-Allow-Methods'] = 'GET,PUT,POST,DELETE,OPTIONS'
            return res

    @app.after_request
    def add_cors_headers(response):
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization,X-Sensor-Key,X-Requested-With'
        response.headers['Access-Control-Allow-Methods'] = 'GET,PUT,POST,DELETE,OPTIONS'
        # Never cache rendered pages, so the dashboard can't be shown from the
        # browser cache after logout / reopening without signing in again.
        if response.mimetype == 'text/html':
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            response.headers['Pragma'] = 'no-cache'
        return response
        
    # Register API & Views Blueprints
    from routes.views import views_bp
    from routes.auth import auth_bp
    from routes.monitoring import monitoring_bp
    from routes.dns import dns_bp
    from routes.alerts import alerts_bp
    from routes.threats import threats_bp
    from routes.devices import devices_bp
    from routes.reports import reports_bp
    from routes.website_activity import website_activity_bp
    from routes.blocking import blocking_bp
    from routes.portal_sessions import portal_sessions_bp
    from routes.sensor import sensor_bp
    
    app.register_blueprint(views_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(monitoring_bp)
    app.register_blueprint(dns_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(threats_bp)
    app.register_blueprint(devices_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(website_activity_bp)
    app.register_blueprint(blocking_bp)
    app.register_blueprint(portal_sessions_bp)
    app.register_blueprint(sensor_bp)
    
    # Initialize sniffer, detection engine, and DNS sinkhole services with app context
    sniffer_service.init_app(app)
    detection_engine.init_app(app)
    dns_sinkhole_service.init_app(app)
    
    with app.app_context():
        try:
            # Auto-create all DB tables on first deploy (safe to run repeatedly)
            db.create_all()
        except Exception as e:
            print(f"[DNSWatch] Note: create_all deferred: {e}")
        # Retried lazily by the sniffer if this attempt fails
        ensure_schema()
        try:
            seed_defaults()
            # Preload detection engine rules from MySQL
            detection_engine.reload_cache()
        except Exception as e:
            print(f"[DNSWatch] Note: Startup DB init deferred: {e}")
            
    return app

if __name__ == '__main__':
    app = create_app()
    port = int(os.getenv("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
