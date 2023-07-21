import click
from flask.cli import AppGroup

from systemdb.webapp.importer.utils import import_file_once, import_dir, update_eol

import_cli = AppGroup('import')


@import_cli.command('file')
@click.argument('filename')
def import_host_command(filename):
    print("[*] Importing file: {0}".format(filename))
    if import_file_once(filename):
        print("[+] File imported! ")
    else:
        print("[-] Import failed!")


@import_cli.command('dir')
@click.argument('name')
def import_dir_command(name):
    import_dir(name)


@import_cli.command('eol')
@click.argument('filename')
def update_eol_command(filename):
    update_eol(filename)