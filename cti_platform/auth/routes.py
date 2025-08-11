# cti_platform/auth/routes.py
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from database.mongo import get_user_by_username, create_user

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        user = get_user_by_username(username)
        if not user or not user.check_password(password):
            flash('Invalid username or password', 'error')
            return render_template('login.html'), 401

        login_user(user)

        role = (getattr(user, 'role', 'public') or 'public').lower()
        return redirect({
            'public': url_for('threat.view_public'),
            'pro':    url_for('threat.view_pro'),
            'admin':  url_for('threat.view_admin'),
        }.get(role, url_for('threat.view_public')))
    return render_template('login.html')

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username  = (request.form.get('username') or '').strip()
        password  = request.form.get('password') or ''
        role      = (request.form.get('role') or 'public').lower()
        interests = [s for s in (request.form.get('interests','').split(',')) if s.strip()]

        # 只允许三种角色；不允许未授权直接注册 admin（有邀请码逻辑的话这里加）
        if role not in {'public','pro','admin'}:
            role = 'public'
        if role == 'admin' and not (current_user.is_authenticated and getattr(current_user,'role','')=='admin'):
            role = 'public'

        if create_user(username, password, role, interests):
            flash('Account created. Please log in.', 'info')
            return redirect(url_for('auth.login'))
        flash('Registration failed. Username may already exist.', 'error')
    return render_template('register.html')

@auth_bp.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))
