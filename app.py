from .login.login import create_app

DB_PATH = '/tmp/challenge.db'
SECRET_KEY = 'cc3a2ef5d33c8557b6e1aadbb582c90599a0392eb6f28ef65f404bbe7606d423'

app = create_app(DB_PATH, SECRET_KEY)