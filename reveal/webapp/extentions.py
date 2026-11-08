from flask_babel import Babel
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect

babel = Babel()
csrf = CSRFProtect()
login_manager = LoginManager()
