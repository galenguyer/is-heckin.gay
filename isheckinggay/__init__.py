import os
import subprocess
import urllib.parse
from base64 import b64encode, b64decode
from pathlib import Path

from flask import Flask, render_template, send_from_directory, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
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
        api_key='',
        git_url='')
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