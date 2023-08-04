from systemdb.core.extentions import db


class EoL(db.Model):
    __tablename__ = "EoL"
    id = db.Column(db.Integer, primary_key=True)
    OS = db.Column(db.String, nullable=True)
    Version = db.Column(db.String, nullable=True)
    OSVersion = db.Column(db.String, nullable=True)
    Build = db.Column(db.String, nullable=True)
    ServiceOption = db.Column(db.String, nullable=True)
    EndOfService = db.Column(db.Boolean, nullable=True)
    StartDate = db.Column(db.DateTime, nullable=True)
    MainstreamEndDate = db.Column(db.DateTime, nullable=True)
    ExtendedEndDate = db.Column(db.DateTime, nullable=True)
    Source = db.Column(db.String, nullable=True)

    def __repr__(self):
        return self.OS

    def __str__(self):
        return self.OS