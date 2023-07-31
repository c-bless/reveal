from systemdb.core.extentions import db


class ImportedFile(db.Model):
    __tablename__ = "ImportedFile"
    id = db.Column(db.Integer, primary_key=True)
    Hash = db.Column(db.String(), unique=True, nullable=False)

    @staticmethod
    def find_by_hash(hash):
        return ImportedFile.query.filter(ImportedFile.Hash == hash).first()

    @staticmethod
    def is_imported(hash):
        imported =  ImportedFile.query.filter(ImportedFile.Hash == hash).first()
        if imported:
            return True
        else:
            return False


class UploadedFile(db.Model):
    __tablename__ = "UploadedFile"
    id = db.Column(db.Integer, primary_key=True)
    UUID = db.Column(db.String(), unique=True, nullable=True)
    OriginalFilename = db.Column(db.String(), unique=False, nullable=False)
    Fullpath = db.Column(db.String(), unique=False, nullable=False)
    Imported = db.Column(db.Boolean(), default=False)

