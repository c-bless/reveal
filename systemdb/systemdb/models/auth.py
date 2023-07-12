from .db import db
from werkzeug.security import generate_password_hash, check_password_hash


class AuthUser(db.Model):
    UUID = db.Column(db.String(100), primary_key=True)
    Password_hash = db.Column(db.String(256))
    Username = db.Column(db.String(256), unique=True)
    API_TOKEN = db.Column(db.String(256), unique=True)
    Active = db.Column(db.Boolean(), default=True)

    def is_authenticated(self):
        return True

    def is_active(self):
        return self.Active

    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.UUID)

    def set_password(self, password):
        self.Password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.Password_hash, password)
