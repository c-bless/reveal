import hashlib
import os
import uuid

from lxml import etree

from reveal.core.extentions import db
from reveal.core.models.eol import EoL
from reveal.core.models.files import UploadedFile

# legacy importer for files of the SystemInfoCollector < 0.7
from reveal.core.importer.hosts import import_host as legacy_import_host
from reveal.core.importer.hosts import import_sysinfo_collector as legacy_import_sysinfo_collector
from reveal.core.importer.domain import import_domain_collector
# importer for XML and JSON files of the SystemInfoCollector >= 0.7
from reveal.core.importer.sysinfo import is_sysinfo_json
from reveal.core.importer.sysinfo import is_sysinfo_xml
from reveal.core.importer.sysinfo import import_sysinfo_json
from reveal.core.importer.sysinfo import import_sysinfo_xml
from reveal.core.importer.sysinfo import load_json

# file types that can be imported
IMPORT_EXTENSIONS = ('.xml', '.json')

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
        uploaded_file = UploadedFile.find_by_hash(hash)
        if uploaded_file:
            # File has been uploaded via web interface
            if uploaded_file.Imported:
                # already imported, no additional import
                return False
            else:
                # not yet imported -> Import file
                uploaded_file.Imported = True
                db.session.commit()
                import_file(filename)
                return True
        else:
            # File has not been uploaded via web interface, import via CLI command
            print("not uploaded yet")
            uploaded_file = UploadedFile()
            uploaded_file.Hash = hash
            uploaded_file.OriginalFilename = os.path.basename(filename)
            uploaded_file.Fullpath = filename
            uploaded_file.UUID = str(uuid.uuid4())
            uploaded_file.Imported = True
            db.session.add(uploaded_file)
            db.session.commit()

            print("importing file {0}".format(uploaded_file.OriginalFilename))
            import_file(filename)
            print("File imported")

            return True
    except Exception as e:
        db.session.rollback()
        return False


def _is_json(content: bytes) -> bool:
    """ JSON files start with '{' or '[' (after an optional BOM / whitespace). """
    for bom in (b'\xef\xbb\xbf', b'\xff\xfe', b'\xfe\xff'):
        if content.startswith(bom):
            return content[len(bom):].replace(b'\x00', b'').lstrip()[:1] in (b'{', b'[')
    return content.lstrip()[:1] in (b'{', b'[')


def import_xml(root):
    """
    Imports a parsed XML document. Files of the SystemInfoCollector >= 0.7 are imported with the new importer, older
    files with the legacy importer.
    """
    if root.tag == "SystemInfoCollector":
        if is_sysinfo_xml(root):
            import_sysinfo_xml(root=root)
        else:
            legacy_import_sysinfo_collector(root=root)
    elif root.tag == "Host":
        # initial version of SystemCollector
        legacy_import_host(root=root)
    elif root.tag == "DomainCollector":
        import_domain_collector(root=root)
    else:
        raise ValueError("Unknown XML format (root element: {0})".format(root.tag))


def import_json(data):
    """
    Imports the content of a JSON file (SystemInfoCollector >= 0.7).
    """
    if is_sysinfo_json(data):
        import_sysinfo_json(data)
    else:
        raise ValueError("Unknown JSON format")


# File has been uploaded via web interface
def import_file(filename):
    """
    Imports a XML or JSON file. The format is detected by the content of the file (not by the file extension).
    """
    with open(filename, 'rb') as f:
        content = f.read()

    if _is_json(content):
        import_json(load_json(content))
    else:
        root = etree.XML(content)
        if etree.iselement(root):
            import_xml(root)


def import_host(filename):
    """
    Imports the output (XML or JSON) of the SystemInfoCollector.
    """
    import_file(filename)


def import_domain(filename):
    with open(filename, 'rb') as f:
        xml = f.read()
    root = etree.XML(xml)
    if etree.iselement(root):
        import_domain_collector(root=root)


def import_dir(name):
    for filename in os.listdir(name):
        if filename.lower().endswith(IMPORT_EXTENSIONS):
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
