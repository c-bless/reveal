from .db import db


class EoL(db.Model):
    __tablename__ = "EoL"
    id = db.Column(db.Integer, primary_key=True)
    OS = db.Column(db.String, nullable=True)
    Version = db.Column(db.String, nullable=True)
    OSVersion = db.Column(db.String, nullable=True)
    Build = db.Column(db.String, nullable=True)
    ServiceOption = db.Column(db.String, nullable=True)
    EndOfService = db.Column(db.Boolean, nullable=True)
    ActiveSupport = db.Column(db.String, nullable=True)
    SecuritySupport = db.Column(db.String, nullable=True)