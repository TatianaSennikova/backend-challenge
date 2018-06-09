from flask_sqlalchemy import SQLAlchemy
from itsdangerous import TimedJSONWebSignatureSerializer as TimedSerializer, URLSafeSerializer, BadSignature, \
    SignatureExpired
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_confirmed = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f"User {self.email}"

    def __init__(self, email, password):
        self.email = email
        self.set_password(password)

    @classmethod
    def get_user_if_valid_auth_token(cls, token, secret_key):
        token_serializer = TimedSerializer(secret_key)
        try:
            email = token_serializer.loads(token)
        except SignatureExpired:
            return None
        except BadSignature:
            return None
        user = cls.query.filter_by(email=email).one_or_none()
        return user

    @classmethod
    def get_user_if_valid_email_token(cls, token, secret_key):
        token_serializer = URLSafeSerializer(secret_key)
        try:
            email = token_serializer.loads(token)
        except BadSignature:
            return None
        user = cls.query.filter_by(email=email).one_or_none()
        return user

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def generate_auth_token(self, secret_key, expiration=600):
        token_serializer = TimedSerializer(secret_key, expires_in=expiration)
        return token_serializer.dumps(self.email)

    def generate_email_token(self, secret_key):
        token_serializer = URLSafeSerializer(secret_key)
        return token_serializer.dumps(self.email)
