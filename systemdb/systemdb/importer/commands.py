import click
from flask.cli import AppGroup
from lxml import etree
import os
from ..models.db import db

from .hosts import import_host, import_sysinfo_collector
from .domain import import_domain_collector
from ..models.eol import EoL

import_cli = AppGroup('import')


@import_cli.command('host')
@click.argument('filename')
def import_host_command(filename):
    with open(filename, 'rb') as f:
        xml = f.read()
    root = etree.XML(xml)
    if etree.iselement(root):
        if root.tag == "SystemInfoCollector":
            print("[*] Importing SystemInfoCollector output")
            import_sysinfo_collector(root=root)
        elif root.tag == "Host":
            # initial version of SystemCollector
            print("[*] Importing SystemInfoCollector output")
            import_host(root=root)


@import_cli.command('domain')
@click.argument('filename')
def import_domain_command(filename):
    with open(filename, 'rb') as f:
        xml = f.read()
    root = etree.XML(xml)
    if etree.iselement(root):
        import_domain_collector(root=root)


@import_cli.command('dir')
@click.argument('name')
def import_dir_command(name):
    for filename in os.listdir(name):
        if filename.endswith('.xml'):
            fullname = os.path.join(name, filename)
            print("[*] Trying to parse file: {0}".format(fullname))
            with open(fullname, 'rb') as f:
                xml = f.read()
            root = etree.XML(xml)
            if etree.iselement(root):
                if root.tag == "DomainCollector":
                    print("[*] Importing DomainCollector output")
                    import_domain_collector(root=root)
                elif root.tag == "SystemInfoCollector":
                    print("[*] Importing SystemInfoCollector output")
                    import_sysinfo_collector(root=root)
                elif root.tag == "Host":
                    # initial version of SystemCollector
                    print("[*] Importing SystemInfoCollector output")
                    import_host(root=root)


@import_cli.command('eol')
@click.argument('filename')
def update_eol_command(filename):
    import csv
    with open(filename) as csv_file:
        csv_reader = csv.reader(csv_file)
        i = 0
        for row in csv_reader:
            if i > 0:
                eos = True
                if row[5].lower() == "false":
                    eos = False
                eol = EoL()
                eol.OS = row[0]
                eol.Version = row[1]
                eol.OSVersion = row[2]
                eol.Build = row[3]
                eol.ServiceOption = row[4]
                eol.EndOfService = eos
                eol.ActiveSupport = row[6]
                eol.SecuritySupport = row[7]
                db.session.add(eol)
            i += 1
    db.session.commit()
