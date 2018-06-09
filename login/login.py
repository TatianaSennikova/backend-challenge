from flask import Flask, request, jsonify
from .models import db, User
from jsonschema import Draft4Validator

USER_DATA_SCHEMA = {
    "type": "object",
    "properties": {
        "email": {
            "type": "string",
            "pattern": '[\w._+]+[@]\w+[.]\w+',
            "minLength": 5,
            "maxLength": 120,
        },
        "password": {
            "type": "string",
            "minLength": 5,
            "maxLength": 120,
        },
    },
    "required": ["email", "password"],
    "additionalProperties": False
}


def get_response_with_json_and_status_code(message, status):
    response = jsonify(message=message)
    response.status_code = status
    return response


def get_errors_from_schema_validation_for_request(request_json, schema=USER_DATA_SCHEMA):
    validator = Draft4Validator(schema)
    errors = validator.iter_errors(request_json)
    error_messages = [{"property": error.path.pop() if error.path else "",
                       "message": error.message if error.validator != 'pattern' else "Incorrect format"}
                      for error in errors]
    return error_messages


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
                return get_response_with_json_and_status_code('Welcome!', 200)
        return get_response_with_json_and_status_code('Please login as a valid user', 401)

    @app.route('/register', methods=['POST'])
    def register():
        try:
            request_json = request.json
            errors = get_errors_from_schema_validation_for_request(request_json)
            if errors:
                return get_response_with_json_and_status_code(errors, 400)
        except:
            return get_response_with_json_and_status_code("Request body must be valid JSON", 400)

        email = request_json['email']
        password = request_json['password']
        user = User.query.filter_by(email=email).one_or_none()
        if user and user.is_confirmed:
            return get_response_with_json_and_status_code("Email has been registered already", 400)
        if not user:
            user = User(email=email, password=password)
            db.session.add(user)
            db.session.commit()
        send_confirmation_email(user)
        return get_response_with_json_and_status_code("Email confirmation link is sent", 201)

    def send_confirmation_email(user):
        confirmation_link = User.generate_email_token(user, secret_key)
        app.logger.info(f"Confirm the email: {request.url_root}confirm/{confirmation_link}")

    @app.route('/confirm/<email_token>', methods=['GET'])
    def confirm_email(email_token):
        user = User.get_user_if_valid_email_token(email_token, secret_key)
        if not user:
            return get_response_with_json_and_status_code("Confirmation link is invalid", 404)
        user.is_confirmed = True
        db.session.commit()
        return get_response_with_json_and_status_code("Email is confirmed", 201)

    @app.route('/login', methods=['POST'])
    def login():
        try:
            request_json = request.json
            errors = get_errors_from_schema_validation_for_request(request_json)
            if errors:
                return get_response_with_json_and_status_code(errors, 400)
        except:
            return get_response_with_json_and_status_code("Request body must be valid JSON", 400)

        email = request_json['email']
        password = request_json['password']
        user = get_user_if_valid_login(email, password)
        if user:
            return get_response_with_auth_token(user)
        return get_response_with_json_and_status_code("Email and/or password are invalid", 401)

    def get_user_if_valid_login(email, password):
        confirmed_user = User.query.filter_by(email=email, is_confirmed=True).one_or_none()
        if not confirmed_user or not confirmed_user.check_password(password):
            return None
        return confirmed_user

    def get_response_with_auth_token(user):
        token = user.generate_auth_token(secret_key)
        response = jsonify(token=token.decode("utf-8"))
        response.set_cookie('token', token)
        return response

    return app
