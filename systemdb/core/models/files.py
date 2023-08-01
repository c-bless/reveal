from systemdb.core.extentions import db


class UploadedFile(db.Model):
    __tablename__ = "UploadedFile"
    id = db.Column(db.Integer, primary_key=True)
    Hash = db.Column(db.String(), unique=True, nullable=False)
    UUID = db.Column(db.String(), unique=True, nullable=True)
    OriginalFilename = db.Column(db.String(), unique=False, nullable=False)
    Fullpath = db.Column(db.String(), unique=False, nullable=False)
    Imported = db.Column(db.Boolean(), default=False)

    @staticmethod
    def find_by_uuid(uid):
        return UploadedFile.query.filter(UploadedFile.uuid == hash).first()

    @staticmethod
    def find_by_hash(hash):
        return UploadedFile.query.filter(UploadedFile.Hash == hash).first()

    @staticmethod
    def find_by_OriginalFilename(name):
        return UploadedFile.query.filter(UploadedFile.OriginalFilename == name).first()

    @staticmethod
    def find_all_imported(hash):
        return UploadedFile.query.filter(UploadedFile.Imported == True).all()

    @staticmethod
    def find_all_not_imported(hash):
        return UploadedFile.query.filter(UploadedFile.Imported == False).all()
