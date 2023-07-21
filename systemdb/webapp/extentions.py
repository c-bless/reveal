from flask_babel import Babel
from flask_bootstrap import Bootstrap
from flask_debugtoolbar import DebugToolbarExtension
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect

bootstrap = Bootstrap()
babel = Babel()
toolbar = DebugToolbarExtension()
csrf = CSRFProtect()
login_manager = LoginManager()
