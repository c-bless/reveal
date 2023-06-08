from .db import db


class EoL(db.Model):
    __tablename__ = "EoL"
    id = db.Column(db.Integer, primary_key=True)
    Release = db.Column(db.String, nullable=True)
    Released = db.Column(db.String, nullable=True)
    ActiveSupport = db.Column(db.String, nullable=True)
    SecuritySupport = db.Column(db.String, nullable=True)
    Build = db.Column(db.String, nullable=True)