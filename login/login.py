from flask import Flask, request, make_response, abort
from .models import db, User
import re
from jsonschema import validate, ValidationError

USER_DATA_SCHEMA = {
    "type": "object",
    "properties": {
        "email": {
            "type": "string",
            "minLength": 5,
            "maxLength": 120,
        },
        "password": {
            "type": "string",
            "minLength": 5,
            "maxLength": 120,
        },
    },
    "required": ["email", "password"]
}


def create_app(db_path, secret_key):
    app = Flask(__name__)

    with app.app_context():
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///{}'.format(db_path)
        app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        app.config['SECRET_KEY'] = secret_key
        db.init_app(app)
        db.create_all()

    @app.route('/', methods=['GET'])
    def index():
        token = request.cookies.get('token')
        if token:
            user = User.get_user_if_valid_auth_token(token, secret_key)
            if user:
                return 'Welcome!', 200
        abort(401, 'Please login as a valid user')

    @app.route('/register', methods=['POST'])
    def register():
        request_json = None
        try:
            request_json = request.json
            validate(request_json, USER_DATA_SCHEMA)
        except ValidationError as e:
            abort(400, e.message)
        except:
            abort(400, "Request body must be valid JSON")

        email = request_json['email']
        if not is_valid_email(email):
            abort(400, 'Email should be in correct format')
        password = request_json['password']

        user = User.query.filter_by(email=email).one_or_none()
        if user:
            if user.is_confirmed:
                abort(400, "Email has been registered")
            user.set_password(password)
            db.session.commit()
        else:
            user = User(email=email, password=password)
            db.session.add(user)
            db.session.commit()
        send_confirmation_email(user)
        return "Email confirmation link is sent", 201

    def is_valid_email(email):
        email_regex = re.compile('[\w._+]+[@]\w+[.]\w+', re.UNICODE)
        return email_regex.match(email)

    def send_confirmation_email(user):
        confirmation_link = User.generate_email_token(user, secret_key)
        app.logger.info(
            'Confirm the email: {}'.format(request.url_root + 'confirm/' + confirmation_link))

    @app.route('/confirm/<email_token>', methods=['GET'])
    def confirm_email(email_token):
        user = User.get_user_if_valid_email_token(email_token, secret_key)
        if not user:
            abort(404, 'Confirmation link is invalid')
        user.is_confirmed = True
        db.session.commit()
        return 'Email confirmed', 201

    @app.route('/login', methods=['POST'])
    def login():
        request_json = None
        try:
            request_json = request.json
            validate(request_json, USER_DATA_SCHEMA)
        except ValidationError as e:
            abort(400, e.message)
        except:
            abort(400, "Request body must be valid JSON")

        email = request_json['email']
        password = request_json['password']

        user = get_user_if_valid_login(email, password)
        if user:
            return get_response_with_auth_token(user)
        abort(401, "Email and/or password are invalid")

    def get_user_if_valid_login(email, password):
        confirmed_user = User.query.filter_by(email=email, is_confirmed=True).one_or_none()
        if not confirmed_user or not confirmed_user.check_password(password):
            return None
        return confirmed_user

    def get_response_with_auth_token(user):
        token = user.generate_auth_token(secret_key)
        response = make_response()
        response.set_cookie('token', token)
        return response

    return app
