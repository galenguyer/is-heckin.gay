from flask_login import UserMixin
from . import db

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True) # primary keys are required by SQLAlchemy
    username = db.Column(db.String(100), unique=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    api_key = db.Column(db.String(100))
    git_url = db.Column(db.String(256))
    is_admin = db.Column(db.Boolean())
    reset_token = db.Column(db.String(256))
