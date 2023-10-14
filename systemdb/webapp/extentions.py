from flask_babel import Babel
from flask_bootstrap import Bootstrap
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect

bootstrap = Bootstrap()
babel = Babel()
csrf = CSRFProtect()
login_manager = LoginManager()
