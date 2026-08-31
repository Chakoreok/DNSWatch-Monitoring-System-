from flask import Blueprint, request, jsonify, redirect, url_for, session
from flask_login import login_user, logout_user, login_required, current_user
from database import db
from models import User
from datetime import datetime

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/api/auth/login', methods=['POST'])
def api_login():
    """
    Validates user credentials against MySQL dnswatch_db users table.
    Establishes an authenticated session on success.
    """
    data = request.get_json() or {}
    username_or_email = (data.get('username') or data.get('email') or '').strip()
    password = (data.get('password') or '').strip()
    
    if not username_or_email or not password:
        return jsonify({
            'success': False,
            'message': 'Username and password are required.'
        }), 400
        
    user = User.query.filter(
        (User.username == username_or_email) | 
        (User.email == username_or_email)
    ).first()
    
    if not user or not user.check_password(password):
        return jsonify({
            'success': False,
            'message': 'Invalid username or password.'
        }), 401
        
    if user.status != 'ACTIVE':
        return jsonify({
            'success': False,
            'message': 'Account is inactive. Contact administrator.'
        }), 403
        
    # Mark session permanent so refreshing browser keeps session active
    session.permanent = True
    login_user(user, remember=False)
    user.last_login = datetime.utcnow()
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': 'Login successful.',
        'user': user.to_dict(),
        'redirect': url_for('views.dashboard_page')
    })

@auth_bp.route('/logout', methods=['GET', 'POST'])
@auth_bp.route('/api/auth/logout', methods=['GET', 'POST'])
def logout():
    """
    Destroys the authenticated session and logs the user out.
    Redirects to the Login Page for standard browser navigation.
    """
    logout_user()
    session.clear()
    
    if request.is_json or (request.method == 'POST' and not request.form):
        resp = jsonify({
            'success': True,
            'message': 'Logged out successfully.',
            'redirect': url_for('views.login_page')
        })
    else:
        resp = redirect(url_for('views.login_page'))
        
    resp.delete_cookie('session')
    resp.delete_cookie('remember_token')
    return resp

@auth_bp.route('/api/auth/me', methods=['GET'])
def api_me():
    if current_user.is_authenticated:
        return jsonify({'authenticated': True, 'user': current_user.to_dict()})
    return jsonify({'authenticated': False, 'user': None})

@auth_bp.route('/api/users', methods=['GET'])
@login_required
def get_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return jsonify({'success': True, 'users': [u.to_dict() for u in users]})

@auth_bp.route('/api/users', methods=['POST'])
@login_required
def create_user():
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Only administrators can create users.'}), 403
        
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '').strip()
    role_id = data.get('role_id', 3)
    full_name = data.get('full_name', '').strip()
    
    if not username or not email or not password:
        return jsonify({'success': False, 'message': 'Username, email and password are required.'}), 400
        
    if User.query.filter((User.username == username) | (User.email == email)).first():
        return jsonify({'success': False, 'message': 'Username or email already in use.'}), 400
        
    user = User(
        username=username,
        email=email,
        role_id=role_id,
        full_name=full_name,
        status='ACTIVE'
    )
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'User created successfully.', 'user': user.to_dict()})
