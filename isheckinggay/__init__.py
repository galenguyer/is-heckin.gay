import os
import secrets
import subprocess
import urllib.parse
from base64 import b64encode, b64decode
from pathlib import Path

from flask import Flask, render_template, send_from_directory, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
from werkzeug.security import generate_password_hash, check_password_hash

APP = Flask(__name__)

# Load file based configuration overrides if present
if os.path.exists(os.path.join(os.getcwd(), 'config.py')):
    APP.config.from_pyfile(os.path.join(os.getcwd(), 'config.py'))
else:
    APP.config.from_pyfile(os.path.join(os.getcwd(), 'config.env.py'))

APP.secret_key = APP.config['SECRET_KEY']

db = SQLAlchemy(APP)
APP.logger.info('SQLAlchemy pointed at ' + repr(db.engine.url))
from .models import *
db.create_all()

login_manager = LoginManager()
login_manager.login_view = '/login'
login_manager.init_app(APP)

@login_manager.user_loader
def load_user(user_id):
        # since the user_id is just the primary key of our user table, use it in the query for the user
        return User.query.get(int(user_id))

_admin_user = User.query.filter_by(username='admin').first()
if _admin_user:
    _admin_user.password = generate_password_hash(APP.config['APP_ADMIN_PASSWORD'], method='sha256')
    db.session.commit()
else:
    _admin_user = User(username='admin', 
        password=generate_password_hash(APP.config['APP_ADMIN_PASSWORD'], method='sha256'), 
        is_admin=True,
        email='',
        api_key=''.join(secrets.token_hex(24)),
        git_url='',
        reset_token=''.join(secrets.token_hex(24)))
    db.session.add(_admin_user)
    db.session.commit()

commit_hash = None
try:
    commit_hash = subprocess.check_output(['git', 'rev-parse', '--short', 'HEAD']) \
        .strip() \
        .decode('utf-8')
# pylint: disable=bare-except
except:
    pass


@APP.route('/static/<path:path>', methods=['GET'])
def _send_static(path):
    return send_from_directory('static', path)
@APP.route('/favicon.ico')
def _send_favicon():
    return send_from_directory('static', 'favicon.ico')


@APP.route('/')
def _index():
    return render_template('home.html', commit_hash=commit_hash)


@APP.route('/login', methods=['GET'])
def _login_get():
    return render_template('login.html', commit_hash=commit_hash)


@APP.route('/login', methods=['POST'])
def login_post():
    username = request.form.get('username') if request.form.get('username') else 'admin'
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(username=username).first()

    # check if the user actually exists
    # take the user-supplied password, hash it, and compare it to the hashed password in the database
    if not user or not check_password_hash(user.password, password):
        flash('Please check your login details and try again.')
        return redirect('/login') # if the user doesn't exist or password is wrong, reload the page

    # if the above check passes, then we know the user has the right credentials
    login_user(user, remember=remember)
    return redirect(request.args.get('next') if request.args.get('next') else '/')


@APP.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/')


@APP.route('/createuser', methods=['GET'])
@login_required
def get_createuser():
    if not current_user.is_admin:
        flash('Not Authorized to View Page')
        return redirect('/')
    return render_template('createuser.html', commit_hash=commit_hash)


@APP.route('/createuser', methods=['POST'])
@login_required
def post_createuser():
    if not current_user.is_admin:
        flash('Not Authorized to View Page')
        return redirect('/')
    username = request.form.get('username')
    email = request.form.get('email')
    user = User.query.filter(or_(User.username==username, User.email==email)).first()
    if user:
        flash('User already exists')
        return redirect('/createuser')
    
    new_user = User(username=username, 
        password=generate_password_hash(request.form.get('password'), method='sha256'), 
        is_admin=(True if request.form.get('admin') else False),
        email=email,
        api_key=''.join(secrets.token_hex(24)),
        git_url='')
    db.session.add(new_user)
    db.session.commit()
    return redirect('/users')


@APP.route('/users', methods=['GET'])
@login_required
def _users():
    if not current_user.is_admin:
        flash('Not Authorized to View Page')
        return redirect('/')
    users = User.query.all()
    return render_template('users.html', users=users, commit_hash=commit_hash)


@APP.route('/profile', methods=['GET'])
@login_required
def _get_profile():
    return render_template('profile.html', user=current_user, commit_hash=commit_hash)


@APP.route('/profile', methods=['POST'])
@login_required
def _update_profile():
    new_email = request.form.get('email')
    if User.query.filter_by(email=new_email).first() and not User.query.filter(or_(User.username==current_user.username, User.email==new_email)).first():
        flash('That email is already in use')
    else:
        current_user.email = new_email
    current_user.git_url = request.form.get('git_url')
    db.session.commit()
    return render_template('profile.html', user=current_user, commit_hash=commit_hash)


@APP.route('/manage', methods=['GET'])
@login_required
def _get_manage():
    if not current_user.is_admin:
        flash('Not Authorized to View Page')
        return redirect('/')
    user = User.query.filter_by(username=request.args.get('user')).first_or_404()
    return render_template('manage.html', user=user, commit_hash=commit_hash)


@APP.route('/manage', methods=['POST'])
@login_required
def _post_manage():
    if not current_user.is_admin:
        flash('Not Authorized to View Page')
        return redirect('/')
    user = User.query.filter_by(username=request.args.get('user')).first_or_404()
    new_email = request.form.get('email')
    if User.query.filter_by(email=new_email).first() and not User.query.filter(or_(User.username==user.username, User.email==new_email)).first():
        flash('That email is already in use')
    else:
        user.email = new_email
    user.git_url = request.form.get('git_url')
    user.api_key = request.form.get('api_key')
    user.is_admin = (True if request.form.get('admin') else False)
    db.session.commit()
    return redirect('/users')


@APP.route('/getpwreset', methods=['GET'])
@login_required
def _get_pw_reset():
    if not request.args.get('user'):
        current_user.reset_token = ''.join(secrets.token_hex(32))
        db.session.commit()
        return redirect('/resetpassword?token='+current_user.reset_token)
    elif current_user.is_admin:
        user = User.query.filter_by(username=request.args.get('user')).first_or_404()
        user.reset_token = ''.join(secrets.token_hex(32))
        db.session.commit()
        return redirect('/resetpassword?token='+user.reset_token)

@APP.route('/resetpassword', methods=['GET'])
def _get_reset_password():
    if not request.args.get('token') or not User.query.filter_by(reset_token=request.args.get('token')).first():
        return render_template('error.html', message='Invalid reset token', commit_hash=commit_hash)
    user = User.query.filter_by(reset_token=request.args.get('token')).first()
    return render_template('resetpassword.html', user=user, commit_hash=commit_hash)

@APP.route('/resetpassword', methods=['POST'])
def _post_reset_password():
    if not request.args.get('token') or not User.query.filter_by(reset_token=request.args.get('token')).first():
        return render_template('error.html', message='Invalid reset token', commit_hash=commit_hash)
    if len(request.form.get('password').strip()) < 8:
        flash('Passwords less than 8 characters are not allowed')
        return redirect(f'/resetpassword?token={request.args.get("token")}')
    user = User.query.filter_by(reset_token=request.args.get('token')).first()
    if len(user.reset_token) < 8:
        return render_template('error.html', message='Invalid reset token', commit_hash=commit_hash)
    user.password = generate_password_hash(request.form.get('password'), method='sha256')
    user.reset_token = ''
    db.session.commit()
    return redirect('/profile' if current_user.is_authenticated else '/login')

    
@APP.route('/<path:path>', methods=['GET'])
def _send_static_root(path):
    return send_from_directory('static', path)
