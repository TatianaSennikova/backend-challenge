import os
import tempfile
import random
import string
import time

import pytest
from itsdangerous import URLSafeSerializer
from .. import login
from ..login import create_app
from ..models import db

INDEX_URL = '/'
REGISTER_URL = '/register'
CONFIRM_URL = '/confirm/'
LOGIN_URL = '/login'

SECRET_KEY = 'testsecretkey'
INVALID_EMAIL_TOKEN = 'emailtoken'


class TestClass:
    @classmethod
    def setup_class(cls):
        cls.db_fd, cls.temp_db_path = tempfile.mkstemp()
        app = create_app(cls.temp_db_path, SECRET_KEY)

        cls.client = app.test_client()

    @classmethod
    def teardown_class(cls):
        os.close(cls.db_fd)
        os.unlink(cls.temp_db_path)

    def setup_method(self):
        self.test_email = 'test.{}@test.test'.format("".join([random.choice(string.ascii_letters) for i in range(5)]))
        self.test_password = "".join([random.choice(string.ascii_letters) for i in range(15)])
        self.email_token = URLSafeSerializer(SECRET_KEY).dumps(self.test_email)

    """
    Tests for /
    """

    def test_index_exists(self):
        response = TestClass.client.get(INDEX_URL)
        assert 404 != response.status_code

    def test_index_method_get_allowed(self):
        response = TestClass.client.get(INDEX_URL)
        assert 405 != response.status_code

    def test_index_method_post_not_allowed(self):
        response = TestClass.client.post(INDEX_URL)
        assert 405 == response.status_code

    def test_index_no_token_401(self):
        response = TestClass.client.get(INDEX_URL, headers={'Get-Cookie': {}})
        assert 401 == response.status_code

    def test_index_incorrect_token_401(self):
        response = TestClass.client.get(INDEX_URL, headers={'Get-Cookie': {'token': 'tokentoken'}})
        assert 401 == response.status_code

    """
    Tests for /register
    """

    def test_register_exists(self):
        response = TestClass.client.get(REGISTER_URL)
        assert 404 != response.status_code

    def test_register_method_get_not_allowed(self):
        response = TestClass.client.get(REGISTER_URL)
        assert 405 == response.status_code

    def test_register_method_post_allowed(self):
        response = TestClass.client.post(REGISTER_URL)
        assert 405 != response.status_code

    def test_register_no_email_400(self):
        response = TestClass.client.post(REGISTER_URL, json={'password': self.test_password})
        assert 400 == response.status_code

    def test_register_no_password_400(self):
        response = TestClass.client.post(REGISTER_URL, json={'email': self.test_email})
        assert 400 == response.status_code

    def test_register_no_email_and_password_400(self):
        response = TestClass.client.post(REGISTER_URL, json={})
        assert 400 == response.status_code

    def test_register_empty_email_400(self):
        response = TestClass.client.post(REGISTER_URL, json={'email': '', 'password': self.test_password})
        assert 400 == response.status_code

    def test_register_empty_password_400(self):
        response = TestClass.client.post(REGISTER_URL, json={'email': self.test_email, 'password': ''})
        assert 400 == response.status_code

    def test_register_empty_email_and_password_400(self):
        response = TestClass.client.post(REGISTER_URL, json={'email': '', 'password': ''})
        assert 400 == response.status_code

    @pytest.mark.parametrize('incorrect_email',
                             ('@.',
                              '2@.',
                              'test@test.',
                              'test@.test',
                              '@test.test',
                              'test@@test.test',
                              '@test.test@',
                              'test'))
    def test_register_incorrect_email_400(self, incorrect_email):
        response = TestClass.client.post(REGISTER_URL, json={'email': incorrect_email, 'password': self.test_password})
        assert 400 == response.status_code

    def test_register_confirmed_email(self):
        response = TestClass.client.post(REGISTER_URL, json={'email': self.test_email, 'password': self.test_password})
        assert 201 == response.status_code

        response = TestClass.client.get(CONFIRM_URL + self.email_token)
        assert 201 == response.status_code

        response = TestClass.client.post(REGISTER_URL, json={'email': self.test_email, 'password': self.test_password})
        assert 400 == response.status_code

    def test_register_another_password(self):
        response = TestClass.client.post(REGISTER_URL, json={'email': self.test_email, 'password': self.test_password})
        assert 201 == response.status_code

        new_password = '12345'
        response = TestClass.client.post(REGISTER_URL, json={'email': self.test_email, 'password': new_password})
        assert 201 == response.status_code

        response = TestClass.client.get(CONFIRM_URL + self.email_token)
        assert 201 == response.status_code

        response = TestClass.client.post(LOGIN_URL, json={'email': self.test_email, 'password': new_password})
        assert 401 == response.status_code

        auth_token = response.headers.get('Set-Cookie', None)
        assert not auth_token

        response = TestClass.client.post(LOGIN_URL, json={'email': self.test_email, 'password': self.test_password})
        assert 200 == response.status_code

        auth_token = response.headers.get('Set-Cookie', None)
        assert auth_token

    """
    Tests for /confirm/<email_token>
    """

    def test_confirm_get_method_allowed(self):
        response = TestClass.client.get(CONFIRM_URL + INVALID_EMAIL_TOKEN)
        assert 405 != response.status_code

    def test_confirm_post_method_not_allowed(self):
        response = TestClass.client.post(CONFIRM_URL + INVALID_EMAIL_TOKEN)
        assert 405 == response.status_code

    def test_confirm_no_token_404(self):
        response = TestClass.client.get(CONFIRM_URL)
        assert 404 == response.status_code

    def test_confirm_incorrect_token_404(self):
        response = TestClass.client.get(CONFIRM_URL + INVALID_EMAIL_TOKEN)
        assert 404 == response.status_code

    def test_confirm_not_registered_email(self):
        response = TestClass.client.get(CONFIRM_URL + self.email_token)
        assert 404 == response.status_code

    """
    Tests for /login
    """

    def test_login_exists(self):
        response = TestClass.client.get(LOGIN_URL)
        assert 404 != response.status_code

    def test_login_method_get_not_allowed(self):
        response = TestClass.client.get(LOGIN_URL)
        assert 405 == response.status_code

    def test_login_method_post_allowed(self):
        response = TestClass.client.post(LOGIN_URL)
        assert 405 != response.status_code

    def test_login_no_email_400(self):
        response = TestClass.client.post(LOGIN_URL, json={'password': self.test_password})
        assert 400 == response.status_code

    def test_login_no_password_400(self):
        response = TestClass.client.post(LOGIN_URL, json={'email': self.test_email})
        assert 400 == response.status_code

    def test_login_no_email_and_password_400(self):
        response = TestClass.client.post(LOGIN_URL, json={})
        assert 400 == response.status_code

    def test_login_empty_email_400(self):
        response = TestClass.client.post(LOGIN_URL, json={'email': '', 'password': self.test_password})
        assert 400 == response.status_code

    def test_login_empty_password_400(self):
        response = TestClass.client.post(LOGIN_URL, json={'email': self.test_email, 'password': ''})
        assert 400 == response.status_code

    def test_login_empty_email_and_password_400(self):
        response = TestClass.client.post(LOGIN_URL, json={'email': '', 'password': ''})
        assert 400 == response.status_code

    def test_login_incorrect_email_401(self):
        response = TestClass.client.post(LOGIN_URL,
                                         json={'email': self.test_email + '1', 'password': self.test_password})
        assert 401 == response.status_code

    def test_login_incorrect_password_401(self):
        response = TestClass.client.post(LOGIN_URL,
                                         json={'email': self.test_email, 'password': self.test_password + '1'})
        assert 401 == response.status_code

    def test_login_incorrect_email_and_password_401(self):
        response = TestClass.client.post(LOGIN_URL,
                                         json={'email': self.test_email + '1', 'password': self.test_password + '1'})
        assert 401 == response.status_code

    def test_login_not_registered_email(self):
        response = TestClass.client.post(LOGIN_URL, json={'email': self.test_email, 'password': self.test_password})
        assert 401 == response.status_code

        auth_token = response.headers.get('Set-Cookie', None)
        assert not auth_token

    def test_login_not_confirmed_email(self):
        response = TestClass.client.post(REGISTER_URL, json={'email': self.test_email, 'password': self.test_password})
        assert 201 == response.status_code

        response = TestClass.client.post(LOGIN_URL, json={'email': self.test_email, 'password': self.test_password})
        assert 401 == response.status_code

        auth_token = response.headers.get('Set-Cookie', None)
        assert not auth_token

    """
    Full path tests
    """

    def test_happy_path_register_confirm_login(self):
        response = TestClass.client.post(REGISTER_URL, json={'email': self.test_email, 'password': self.test_password})
        assert 201 == response.status_code

        response = TestClass.client.get(CONFIRM_URL + self.email_token)
        assert 201 == response.status_code

        response = TestClass.client.post(LOGIN_URL, json={'email': self.test_email, 'password': self.test_password})
        assert 200 == response.status_code

        auth_token = response.headers.get('Set-Cookie', None)
        assert auth_token

        response = TestClass.client.get(INDEX_URL, headers={'Get-Cookie': {'token': auth_token}})
        assert 200 == response.status_code

    def test_happy_path_register_register_confirm_login(self):
        response = TestClass.client.post(REGISTER_URL, json={'email': self.test_email, 'password': self.test_password})
        assert 201 == response.status_code

        response = TestClass.client.post(REGISTER_URL, json={'email': self.test_email, 'password': self.test_password})
        assert 201 == response.status_code

        response = TestClass.client.get(CONFIRM_URL + self.email_token)
        assert 201 == response.status_code

        response = TestClass.client.post(LOGIN_URL, json={'email': self.test_email, 'password': self.test_password})
        assert 200 == response.status_code

        auth_token = response.headers.get('Set-Cookie', None)
        assert auth_token

        response = TestClass.client.get(INDEX_URL, headers={'Get-Cookie': {'token': auth_token}})
        assert 200 == response.status_code

    def test_happy_path_register_confirm_confirm_login(self):
        response = TestClass.client.post(REGISTER_URL, json={'email': self.test_email, 'password': self.test_password})
        assert 201 == response.status_code

        response = TestClass.client.get(CONFIRM_URL + self.email_token)
        assert 201 == response.status_code

        response = TestClass.client.get(CONFIRM_URL + self.email_token)
        assert 201 == response.status_code

        response = TestClass.client.post(LOGIN_URL, json={'email': self.test_email, 'password': self.test_password})
        assert 200 == response.status_code

        auth_token = response.headers.get('Set-Cookie', None)
        assert auth_token

        response = TestClass.client.get(INDEX_URL, headers={'Get-Cookie': {'token': auth_token}})
        assert 200 == response.status_code

    def test_happy_path_register_confirm_login_login(self):
        response = TestClass.client.post(REGISTER_URL, json={'email': self.test_email, 'password': self.test_password})
        assert 201 == response.status_code

        response = TestClass.client.get(CONFIRM_URL + self.email_token)
        assert 201 == response.status_code

        response = TestClass.client.post(LOGIN_URL, json={'email': self.test_email, 'password': self.test_password})
        assert 200 == response.status_code

        auth_token_first = response.headers.get('Set-Cookie', None)
        assert auth_token_first

        time.sleep(1)
        response = TestClass.client.post(LOGIN_URL, json={'email': self.test_email, 'password': self.test_password})
        assert 200 == response.status_code

        auth_token_second = response.headers.get('Set-Cookie', None)
        assert auth_token_second

        assert auth_token_first != auth_token_second

        response = TestClass.client.get(INDEX_URL, headers={'Get-Cookie': {'token': auth_token_first}})
        assert 200 == response.status_code

        response = TestClass.client.get(INDEX_URL, headers={'Get-Cookie': {'token': auth_token_second}})
        assert 200 == response.status_code
