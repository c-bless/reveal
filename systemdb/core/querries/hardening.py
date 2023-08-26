from sqlalchemy import or_
from sqlalchemy import and_

from systemdb.core.models.sysinfo import Service
from systemdb.core.models.sysinfo import ServiceACL


def find_uqsp() -> list[Service]:
    services = Service.query.filter(and_(Service.PathName.notlike('"%'),
                              Service.PathName.contains(" "),
                              Service.PathName.notlike('C:\\Windows%'))).all()
    return services


def find_modifiable_services() -> list[ServiceACL]:
    acls = ServiceACL.query.filter(
        or_(
            and_(
                ServiceACL.AccessRight.ilike("%Modify%"),
                ServiceACL.AccountName.notilike("%System"),
                ServiceACL.AccountName.notilike("%TrustedInstaller"),
                ServiceACL.AccountName.notilike("%Administra%"),
            ),
            and_(
                ServiceACL.AccessRight.ilike("%FullControl%"),
                ServiceACL.AccountName.notilike("%System"),
                ServiceACL.AccountName.notilike("%TrustedInstaller"),
                ServiceACL.AccountName.notilike("%Administra%"),
            )
        )
    ).all()
    return acls