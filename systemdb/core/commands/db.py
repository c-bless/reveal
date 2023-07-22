
from flask.cli import AppGroup
from flask import current_app

from systemdb.webapp.importer.utils import update_eol
from systemdb.core.extentions import db
from systemdb.core.commands.auth import create_user
from systemdb.core.models.sysinfo import Host, User, Group, GroupMember,Share, ShareACL, ShareACLNTFS, ServiceACL, Service, Hotfix,ConfigCheck, PSInstalledVersions, NetIPAddress, NetAdapter, Product, Printer, DefenderSettings
from systemdb.core.models.activedirectory import ADDomain
from systemdb.core.models.activedirectory import ADForest, ADForestSite,ADUser, ADUserMembership, ADForestGlobalCatalog, ADGroup , ADTrust, ADComputer,ADGroupMember, ADPasswordPolicy, ADDomainController, ADDCServerRole, ADOperationMasterRole
from systemdb.core.models.eol import EoL
from systemdb.core.models.files import ImportedFile
db_cli = AppGroup('db')


@db_cli.command('create')
def create_db():
    print("[*] Creating/Recreating database:")
    db.metadata.drop_all(bind=db.engine)
    db.metadata.create_all(bind=db.engine)
    db.session.commit()

    update_dir = current_app.config.get("UPDATE_DATA_DIR")
    update_eol("{0}win-support-dates.csv".format(update_dir))

    create_user("admin")


@db_cli.command('clear')
def clear_db():
    print("[*] Creating/Recreating database:")
    db.session.query(EoL).delete()
    db.session.query(Host).delete()
    db.session.query(User).delete()
    db.session.query(Group).delete()
    db.session.query(GroupMember).delete()
    db.session.query(Share).delete()
    db.session.query(ShareACL).delete()
    db.session.query(ShareACLNTFS).delete()
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
    db.session.query(ADDomain).delete()
    db.session.query(ADForest).delete()
    db.session.query(ADForestSite).delete()
    db.session.query(ADUser).delete()
    db.session.query(ADUserMembership).delete()
    db.session.query(ADForestGlobalCatalog).delete()
    db.session.query(ADGroup).delete()
    db.session.query(ADTrust).delete()
    db.session.query(ADComputer).delete()
    db.session.query(ADGroupMember).delete()
    db.session.query(ADPasswordPolicy).delete()
    db.session.query(ADDomainController).delete()
    db.session.query(ADDCServerRole).delete()
    db.session.query(ADOperationMasterRole).delete()
    db.session.query(ImportedFile).delete()
    db.session.commit()
