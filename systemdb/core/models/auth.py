from systemdb.core.extentions import db
from werkzeug.security import generate_password_hash, check_password_hash
import uuid

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

    @staticmethod
    def find_by_UUID(uid: uuid.UUID) :
        uid = str(uuid.UUID(uid)) # verfiy that parameter is a valid UUID
        return AuthUser.query.filter(AuthUser.UUID == uid).first()

    @staticmethod
    def find_by_username(name: str):
        return AuthUser.query.filter(AuthUser.Username == name).first()

    @staticmethod
    def find_by_token(token: str):
        return AuthUser.query.filter(AuthUser.API_TOKEN == token).first()

    @staticmethod
    def find_all():
        return AuthUser.query.all()