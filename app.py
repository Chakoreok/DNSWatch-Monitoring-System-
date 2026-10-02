import os
from flask import Flask
from flask_login import LoginManager
from config import Config
from database import db
from models import User
from services.sniffer import sniffer_service
from services.detection_engine import detection_engine
from services.dns_sinkhole import dns_sinkhole_service

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
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
    
    # Initialize sniffer, detection engine, and DNS sinkhole services with app context
    sniffer_service.init_app(app)
    detection_engine.init_app(app)
    dns_sinkhole_service.init_app(app)
    
    with app.app_context():
        try:
            # Auto-create all DB tables on first deploy (safe to run repeatedly)
            db.create_all()
            # Preload detection engine rules from MySQL
            detection_engine.reload_cache()
        except Exception as e:
            print(f"[DNSWatch] Note: Startup DB init deferred: {e}")
            
    return app

if __name__ == '__main__':
    app = create_app()
    port = int(os.getenv("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
