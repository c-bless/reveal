
from flask.cli import AppGroup
from flask import current_app

from systemdb.webapp.importer.utils import update_eol
from systemdb.core.extentions import db
from systemdb.core.commands.auth import create_user

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
    db.metadata.drop_all(bind=db.engine)
    db.metadata.create_all(bind=db.engine)
    db.session.commit()
