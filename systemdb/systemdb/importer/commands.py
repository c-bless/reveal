import click
from flask.cli import AppGroup
from .hosts import import_host
from .domain import import_domain

import_cli = AppGroup('import')

@import_cli.command('host')
@click.argument('filename')
def import_host_command(filename):
    import_host(filename=filename)

@import_cli.command('domain')
@click.argument('filename')
def import_domain_command(filename):
    import_domain(filename=filename)

