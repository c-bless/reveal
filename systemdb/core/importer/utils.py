import hashlib
import os

from lxml import etree

from systemdb.core.extentions import db
from systemdb.core.models.eol import EoL
from systemdb.core.models.files import ImportedFile

from systemdb.core.importer.hosts import import_host, import_sysinfo_collector
from systemdb.core.importer.domain import import_domain_collector

BUF_SIZE = 65536


def hash_file(filename):
    """
    Calculate a SHA-512 hash from the given file.
    :param filename: File from which the hash should be calculated
    :return:
    """
    sha512 = hashlib.sha512()

    with open(filename, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            sha512.update(data)

    return sha512.hexdigest()


def import_file_once(filename):
    hash = hash_file(filename)

    try:
        imported_file = ImportedFile()
        imported_file.Hash = hash
        db.session.add(imported_file)
        db.session.commit()

        print("importing file {0}".format(imported_file))
        import_file(filename)
        print("File imported")

        return True
    except Exception as e:
        print(e)
        return False


def import_file(filename):
    with open(filename, 'rb') as f:
        xml = f.read()

    root = etree.XML(xml)
    if etree.iselement(root):
        if root.tag == "SystemInfoCollector":
            import_sysinfo_collector(root=root)
        if root.tag == "Host":
            import_host(root=root)
        if root.tag == "DomainCollector":
            import_domain_collector(root=root)


def import_host(filename):
    with open(filename, 'rb') as f:
        xml = f.read()
    root = etree.XML(xml)
    if etree.iselement(root):
        if root.tag == "SystemInfoCollector":
            import_sysinfo_collector(root=root)
        elif root.tag == "Host":
            # initial version of SystemCollector
            print("[*] Importing SystemInfoCollector output")
            import_host(root=root)


def import_domain(filename):
    with open(filename, 'rb') as f:
        xml = f.read()
    root = etree.XML(xml)
    if etree.iselement(root):
        import_domain_collector(root=root)


def import_dir(name):
    for filename in os.listdir(name):
        if filename.endswith('.xml'):
            fullname = os.path.join(name, filename)
            print("[*] Importing file: {0}".format(filename))
            if import_file_once(fullname):
                print("[+] File imported! ")
            else:
                print("[-] Import failed!")


def update_eol(filename):
    import csv
    from datetime import datetime
    db.session.query(EoL).delete()
    db.session.commit()
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
                try:
                    eol.StartDate = datetime.strptime(row[7], "%Y-%m-%d")
                except:
                    pass
                try:
                    eol.MainstreamEndDate = datetime.strptime(row[8], "%Y-%m-%d")
                except:
                    pass
                try:
                    eol.ExtendedEndDate = datetime.strptime(row[9], "%Y-%m-%d")
                except:
                    pass
                eol.Source = row[10]
                db.session.add(eol)
            i += 1
    db.session.commit()