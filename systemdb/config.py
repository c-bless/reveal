import os
import logging

basedir = os.path.abspath(os.path.join(os.path.dirname(__file__),"."))
parentdir = os.path.abspath(os.path.join(os.path.dirname(__file__),".."))


class AppConfig(object):
    # import secrets
    # secrets.token_hex(32)
    SECRET_KEY = os.environ.get('SECRET_KEY') or \
                 '632761b4a7ffb045d2fe95b255bf834fedeacd083b86aea12817c440db4c2440' # change me!
    SITE_NAME = 'SYSTEMDB'
    SITE_ROOT_URL = 'http://127.0.0.1:8000'
    LOG_LEVEL = logging.DEBUG
    DEBUG=False

    # 200 MB
    MAX_CONTENT_LENGTH = 1024 * 1024 * 200
    UPLOAD_EXTENSIONS = ['.xml']
    UPLOAD_DIR = os.environ.get('UPLOAD_DIR') or \
                 os.path.abspath(os.path.join(basedir, os.pardir))+ "/uploads/"
    REPORT_DIR = os.environ.get('REPORT_DIR') or \
                 os.path.abspath(os.path.join(basedir, os.pardir))+ "/reports/"
    UPDATE_DATA_DIR = os.environ.get('UPDATE_DATA_DIR') or \
                      os.path.abspath(os.path.join(basedir, os.pardir))+ "/update-data/"

    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
                              'sqlite:///' + os.path.join(parentdir, 'systemdb.sqlite')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_RECORD_QUERIES = True

    # Enable protection agains *Cross-site Request Forgery (CSRF)*
    CSRF_ENABLED = True
    # import secrets
    # secrets.token_hex(32)
    CSRF_SESSION_KEY = os.environ.get('CSRF_SESSION_KEY') or \
                       "2fc5f6bdefad9a0320e93ee56ece5856ab24a5d975bc9ce87bd072e95fc41988" # change me!

    TEMPLATES_AUTO_RELOAD = True

    API_DOCS = os.environ.get('API_DOCS') or 'http://127.0.0.1:8001'

class ApiConfig(object):
    # import secrets
    # secrets.token_hex(32)
    SECRET_KEY = os.environ.get('SECRET_KEY') or \
                 'e2c943e09c7af7282229cd32c32971bba9b6a2a26abbd7f2c0f8b42a856f02af' # change me!
    SITE_ROOT_URL = 'http://127.0.0.1:8001'
    LOG_LEVEL = logging.DEBUG
    DEBUG=False

    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///' + os.path.join(basedir, 'systemdb.sqlite')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_RECORD_QUERIES = True

    # one of swagger-ui(default), redoc, elements, rapidoc, and rapipdf
    DOCS_UI = "swagger-ui"
    OPENAPI_VERSION = '3.0.2'

    USE_PROXY = True

