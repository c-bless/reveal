from sqlalchemy import or_
from sqlalchemy import and_

from systemdb.core.models.sysinfo import FileExistCheck


def find_file_exist(filename: str) -> list[FileExistCheck]:
    fec = FileExistCheck.query.filter(FileExistCheck.File == True).all()
    return fec


def find_file_not_exist(filename: str) -> list[FileExistCheck]:
    fec = FileExistCheck.query.filter(FileExistCheck.File == False).all()
    return fec