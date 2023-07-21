import click
import uuid

from flask.cli import AppGroup

from systemdb.core.extentions import db
from systemdb.core.models.auth import AuthUser

from systemdb.webapp.auth.utils import gen_api_token, gen_initial_pw

user_cli = AppGroup('user')


@user_cli.command('create')
@click.argument('name')
def create_user(name):
    print("[*] Creating user: {0}".format(name))
    initial_pw = gen_initial_pw()
    token = gen_api_token()
    try:
        user = AuthUser()
        user.UUID = str(uuid.uuid4())
        user.Username = name
        user.set_password(initial_pw)
        user.API_TOKEN = token
        db.session.add(user)
        db.session.commit()
        print("[*] User {0} created.".format(name))
        print("[!] Initial password: {0}".format(initial_pw))
        print("[!] API-Token: {0}".format(token))
    except:
        print("[-] Couldn't create user.")