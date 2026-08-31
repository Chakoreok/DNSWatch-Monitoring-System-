from datetime import datetime
from database import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

class BaseModel(db.Model):
    __abstract__ = True
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class Role(BaseModel):
    __tablename__ = 'roles'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    users = db.relationship('User', backref='role', lazy=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description
        }


class User(UserMixin, BaseModel):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=False, default=1)
    full_name = db.Column(db.String(120), nullable=True)
    status = db.Column(db.String(20), nullable=False, default='ACTIVE')
    last_login = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
        
    @property
    def is_admin(self):
        return self.role and self.role.name.lower() == 'administrator'
        
    @property
    def is_analyst(self):
        return self.role and self.role.name.lower() in ('administrator', 'security analyst')
        
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'full_name': self.full_name,
            'role': self.role.name if self.role else 'Viewer',
            'role_id': self.role_id,
            'status': self.status,
            'last_login': self.last_login.strftime('%Y-%m-%d %H:%M:%S') if self.last_login else None,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else None
        }


class MonitoringSession(BaseModel):
    __tablename__ = 'monitoring_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    session_name = db.Column(db.String(100), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    end_time = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(30), nullable=False, default='ACTIVE')  # ACTIVE, STOPPED
    interface = db.Column(db.String(100), nullable=True)
    total_queries = db.Column(db.Integer, nullable=False, default=0)
    safe_queries = db.Column(db.Integer, nullable=False, default=0)
    suspicious_queries = db.Column(db.Integer, nullable=False, default=0)
    malicious_queries = db.Column(db.Integer, nullable=False, default=0)
    blocked_queries = db.Column(db.Integer, nullable=False, default=0)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    logs = db.relationship('DNSLog', backref='session', lazy='dynamic')
    
    def to_dict(self):
        return {
            'id': self.id,
            'session_name': self.session_name,
            'start_time': self.start_time.strftime('%Y-%m-%d %H:%M:%S') if self.start_time else None,
            'end_time': self.end_time.strftime('%Y-%m-%d %H:%M:%S') if self.end_time else None,
            'status': self.status,
            'interface': self.interface,
            'total_queries': self.total_queries,
            'safe_queries': self.safe_queries,
            'suspicious_queries': self.suspicious_queries,
            'malicious_queries': self.malicious_queries,
            'blocked_queries': self.blocked_queries
        }


class DNSLog(BaseModel):
    __tablename__ = 'dns_logs'
    
    id = db.Column(db.BigInteger, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('monitoring_sessions.id'), nullable=True, index=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    client_ip = db.Column(db.String(45), nullable=False, index=True)
    client_port = db.Column(db.Integer, nullable=True)
    query_domain = db.Column(db.String(255), nullable=False, index=True)
    query_type = db.Column(db.String(16), nullable=False, default='A', index=True)
    response_ip = db.Column(db.String(255), nullable=True)
    response_code = db.Column(db.String(50), nullable=False, default='NOERROR')
    ttl = db.Column(db.Integer, nullable=False, default=300)
    status = db.Column(db.String(20), nullable=False, default='SAFE', index=True)  # SAFE, SUSPICIOUS, BLOCKED
    detection_reason = db.Column(db.String(255), nullable=True)
    matched_rule_id = db.Column(db.Integer, nullable=True, index=True)
    source = db.Column(db.String(50), nullable=False, default='SCAPY_CAPTURE')
    activity_category = db.Column(db.String(30), nullable=False, default='Standard query')
    
    def to_dict(self):
        return {
            'id': self.id,
            'session_id': self.session_id,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S') if self.timestamp else '',
            'time_only': self.timestamp.strftime('%I:%M:%S %p') if self.timestamp else '',
            'client_ip': self.client_ip,
            'client_port': self.client_port,
            'query_domain': self.query_domain,
            'domain': self.query_domain,
            'query_type': self.query_type,
            'response_ip': self.response_ip or '-',
            'response_code': self.response_code,
            'ttl': self.ttl,
            'status': self.status,
            'detection_reason': self.detection_reason,
            'info': self.activity_category or 'Standard query'
        }


class SecurityAlert(BaseModel):
    __tablename__ = 'security_alerts'
    
    id = db.Column(db.BigInteger, primary_key=True)
    alert_id = db.Column(db.String(30), unique=True, nullable=False, index=True)
    log_id = db.Column(db.BigInteger, db.ForeignKey('dns_logs.id'), nullable=True, index=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    severity = db.Column(db.String(20), nullable=False, default='HIGH', index=True)  # HIGH, MEDIUM, LOW
    domain = db.Column(db.String(255), nullable=False, index=True)
    client_ip = db.Column(db.String(45), nullable=False, index=True)
    alert_type = db.Column(db.String(100), nullable=False, index=True)  # Malicious Domain Match, Suspicious Domain Rule, High DNS Query Frequency, Blocked domain request
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(30), nullable=False, default='New', index=True)  # New, Acknowledged, Resolved
    resolved_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    resolved_at = db.Column(db.DateTime, nullable=True)
    
    log = db.relationship('DNSLog', backref='alerts', lazy=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'alert_id': self.alert_id,
            'log_id': self.log_id,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S') if self.timestamp else '',
            'time_only': self.timestamp.strftime('%I:%M:%S %p') if self.timestamp else '',
            'severity': self.severity,
            'domain': self.domain,
            'client_ip': self.client_ip,
            'alert_type': self.alert_type,
            'description': self.description,
            'status': self.status,
            'resolved_at': self.resolved_at.strftime('%Y-%m-%d %H:%M:%S') if self.resolved_at else None
        }


class MaliciousDomain(BaseModel):
    __tablename__ = 'malicious_domains'
    
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), unique=True, nullable=False, index=True)
    category = db.Column(db.String(100), nullable=False, default='Malware / Phishing')
    severity = db.Column(db.String(20), nullable=False, default='HIGH')
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), nullable=False, default='Active', index=True)  # Active, Inactive
    added_by = db.Column(db.String(100), nullable=False, default='admin')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'domain': self.domain,
            'category': self.category,
            'severity': self.severity,
            'description': self.description,
            'status': self.status,
            'added_by': self.added_by,
            'added_at': self.created_at.strftime('%b %d, %Y %I:%M %p') if self.created_at else '',
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else ''
        }


class DetectionRule(BaseModel):
    __tablename__ = 'detection_rules'
    
    id = db.Column(db.Integer, primary_key=True)
    rule_name = db.Column(db.String(120), nullable=False)
    rule_type = db.Column(db.String(50), nullable=False, index=True)  # KEYWORD, TLD_BLACKLIST, PATTERN, REGEX, FREQUENCY
    pattern = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(100), nullable=False, default='Suspicious Pattern')
    severity = db.Column(db.String(20), nullable=False, default='MEDIUM')
    action = db.Column(db.String(20), nullable=False, default='Alert')  # Alert, Block
    description = db.Column(db.Text, nullable=True)
    is_active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'rule_name': self.rule_name,
            'rule_type': self.rule_type,
            'type': self.rule_type.capitalize() if self.rule_type else 'Pattern',
            'pattern': self.pattern,
            'condition': self.pattern,
            'category': self.category,
            'severity': self.severity,
            'action': self.action,
            'is_active': bool(self.is_active),
            'status': 'Active' if self.is_active else 'Inactive',
            'last_modified': self.updated_at.strftime('%b %d, %Y %I:%M %p') if self.updated_at else (self.created_at.strftime('%b %d, %Y %I:%M %p') if self.created_at else '')
        }


class FrequencyRuleConfig(BaseModel):
    __tablename__ = 'frequency_rule_config'
    
    id = db.Column(db.Integer, primary_key=True)
    threshold = db.Column(db.Integer, nullable=False, default=100)
    time_window = db.Column(db.Integer, nullable=False, default=60)  # seconds
    action = db.Column(db.String(20), nullable=False, default='Alert')  # Alert, Block
    status = db.Column(db.String(20), nullable=False, default='Active')  # Active, Inactive
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'threshold': self.threshold,
            'time_window': self.time_window,
            'action': self.action,
            'status': self.status,
            'last_modified': self.updated_at.strftime('%b %d, %Y %I:%M %p') if self.updated_at else ''
        }


class Device(BaseModel):
    __tablename__ = 'devices'
    
    id = db.Column(db.Integer, primary_key=True)
    client_ip = db.Column(db.String(45), unique=True, nullable=False, index=True)
    mac_address = db.Column(db.String(50), nullable=True)
    device_name = db.Column(db.String(100), nullable=True)
    device_type = db.Column(db.String(50), nullable=False, default='Desktop/Laptop')
    dns_queries = db.Column(db.Integer, nullable=False, default=0)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    status = db.Column(db.String(20), nullable=False, default='Active')
    
    def to_dict(self):
        return {
            'id': self.id,
            'client_ip': self.client_ip,
            'ip_address': self.client_ip,
            'mac_address': self.mac_address or '-',
            'device_name': self.device_name or f"Host-{self.client_ip.replace('.', '-')}",
            'device_type': self.device_type,
            'dns_queries': self.dns_queries,
            'last_seen': self.last_seen.strftime('%I:%M:%S %p') if self.last_seen else '-',
            'status': self.status
        }


class WebsiteActivity(BaseModel):
    __tablename__ = 'website_activity'
    
    id = db.Column(db.BigInteger, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    domain = db.Column(db.String(255), nullable=False, index=True)
    client_ip = db.Column(db.String(45), nullable=False, index=True)
    device_name = db.Column(db.String(100), nullable=True)
    device_type = db.Column(db.String(50), nullable=False, default='Windows')
    status = db.Column(db.String(20), nullable=False, default='SAFE')  # SAFE, SUSPICIOUS, BLOCKED
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S') if self.timestamp else '',
            'time': self.timestamp.strftime('%I:%M:%S %p') if self.timestamp else '',
            'domain': self.domain,
            'client_ip': self.client_ip,
            'device_name': self.device_name or f"DESKTOP-{self.client_ip.split('.')[-1]}",
            'device_type': self.device_type,
            'status': self.status
        }
