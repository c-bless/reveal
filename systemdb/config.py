import os
import logging

basedir = os.path.abspath(os.path.join(os.path.dirname(__file__),"."))


class Config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'MYSECRET'
    JWT_SECRET_KEY = SECRET_KEY
    SITE_NAME = 'SYSTEMDB'
    SITE_ROOT_URL = 'http://127.0.0.1:5000'
    LOG_LEVEL = logging.DEBUG
    DEBUG=True

    LANGUAGES = ['en', 'de']

    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///' + os.path.join(basedir, 'systemdb.sqlite')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_RECORD_QUERIES = True

    # Enable protection agains *Cross-site Request Forgery (CSRF)*
    CSRF_ENABLED = True
    CSRF_SESSION_KEY = "secret"

    TEMPLATES_AUTO_RELOAD = True