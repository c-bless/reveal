import os
from flask.cli import AppGroup
from flask import current_app

from reveal.core.importer.utils import update_eol
from reveal.core.extentions import db
from reveal.core.models.sysinfo import Host
from reveal.core.models.sysinfo import User
from reveal.core.models.sysinfo import Group
from reveal.core.models.sysinfo import GroupMember
from reveal.core.models.sysinfo import Share
from reveal.core.models.sysinfo import ShareACL
from reveal.core.models.sysinfo import ShareACLNTFS
from reveal.core.models.sysinfo import ServiceACL
from reveal.core.models.sysinfo import Service
from reveal.core.models.sysinfo import Hotfix
from reveal.core.models.sysinfo import ConfigCheck
from reveal.core.models.sysinfo import PSInstalledVersions
from reveal.core.models.sysinfo import NetIPAddress
from reveal.core.models.sysinfo import NetAdapter
from reveal.core.models.sysinfo import Product
from reveal.core.models.sysinfo import Printer
from reveal.core.models.sysinfo import PathACL
from reveal.core.models.sysinfo import PathACLCheck
from reveal.core.models.sysinfo import DefenderSettings
from reveal.core.models.sysinfo import RegistryCheck
from reveal.core.models.sysinfo import FileExistCheck

from reveal.core.models.activedirectory import ADDomain
from reveal.core.models.activedirectory import ADForest
from reveal.core.models.activedirectory import ADForestSite
from reveal.core.models.activedirectory import ADUser
from reveal.core.models.activedirectory import ADUserMembership
from reveal.core.models.activedirectory import ADForestGlobalCatalog
from reveal.core.models.activedirectory import ADGroup
from reveal.core.models.activedirectory import ADTrust
from reveal.core.models.activedirectory import ADComputer
from reveal.core.models.activedirectory import ADGroupMember
from reveal.core.models.activedirectory import ADPasswordPolicy
from reveal.core.models.activedirectory import ADDomainController
from reveal.core.models.activedirectory import ADDCServerRole
from reveal.core.models.activedirectory import ADOperationMasterRole
from reveal.core.models.activedirectory import ADSPN
from reveal.core.models.eol import EoL
from reveal.core.models.files import UploadedFile
db_cli = AppGroup('db')


@db_cli.command('create')
def create_db():
    print("[*] Creating/Recreating database:")
    db.metadata.drop_all(bind=db.engine)
    db.metadata.create_all(bind=db.engine)
    db.session.commit()

    update_dir = current_app.config.get("UPDATE_DATA_DIR")
    update_eol("{0}win-support-dates.csv".format(update_dir))


@db_cli.command('clear')
def clear_db():
    print("[*] Clearing data in database")
    db.session.query(EoL).delete()
    db.session.query(User).delete()
    db.session.query(GroupMember).delete()
    db.session.query(Group).delete()

    db.session.query(ShareACL).delete()
    db.session.query(ShareACLNTFS).delete()
    db.session.query(Share).delete()

    db.session.query(ServiceACL).delete()
    db.session.query(Service).delete()
    
    db.session.query(Hotfix).delete()
    db.session.query(ConfigCheck).delete()
    db.session.query(PSInstalledVersions).delete()
    db.session.query(NetIPAddress).delete()
    db.session.query(NetAdapter).delete()
    db.session.query(Product).delete()
    db.session.query(DefenderSettings).delete()
    db.session.query(Printer).delete()
    db.session.query(RegistryCheck).delete()
    db.session.query(FileExistCheck).delete()
    db.session.query(PathACLCheck).delete()
    db.session.query(PathACL).delete()
    db.session.query(Host).delete()

    db.session.query(PathACLCheck).delete()
    db.session.query(PathACL).delete()
    db.session.query(ADForestSite).delete()
    db.session.query(ADUserMembership).delete()
    db.session.query(ADUser).delete()
    db.session.query(ADForestGlobalCatalog).delete()
    db.session.query(ADGroupMember).delete()
    db.session.query(ADGroup).delete()
    db.session.query(ADTrust).delete()
    db.session.query(ADDCServerRole).delete()
    db.session.query(ADSPN).delete()
    db.session.query(ADComputer).delete()
    db.session.query(ADPasswordPolicy).delete()
    db.session.query(ADOperationMasterRole).delete()
    db.session.query(ADDomainController).delete()
    db.session.query(ADDomain).delete()
    db.session.query(ADForest).delete()
    db.session.query(UploadedFile).delete()
    db.session.commit()


    print("[*] Clearing data in upload directory")
    for f in os.listdir(current_app.config['UPLOAD_DIR']):
        filename = current_app.config['UPLOAD_DIR'] + f
        os.remove(filename)
