import os
from flask import current_app

from io import BytesIO
from docxtpl import DocxTemplate


def generate_docx(template, context):
    doc = DocxTemplate(template)
    doc.render(context)
    f = BytesIO()
    doc.save(f)
    length = f.tell()
    f.seek(0)
    return f


def generate_hosts_docx(template, hosts=[]):
    context = {'hosts': hosts}
    return generate_docx(template=template, context=context)


def generate_hosts_report_docx(template, report, hosts=[]):
    context = {'hosts': hosts, 'report': report}
    return generate_docx(template=template, context=context)


def generate_single_host_docx(template, host=None):
    context = {'host': host}
    return generate_docx(template=template, context=context)


def generate_hotkey_docx(template, report, hotkey_dict=[]):
    context = {'hotkey_dict': hotkey_dict, 'report': report}
    return generate_docx(template=template, context=context)

def generate_configcheck_docx(template, report, checks=[]):
    context = {'checks': checks, 'report': report}
    return generate_docx(template=template, context=context)


def generate_group_report_docx(template, report, groups=[]):
    context = {'groups': groups, 'report': report}
    return generate_docx(template=template, context=context)


def generate_service_report_docx(template, report, services=[]):
    context = {'services': services, 'report': report}
    return generate_docx(template=template, context=context)

def generate_serviceACL_report_docx(template, report, acls=[]):
    context = {'acls': acls, 'report': report}
    return generate_docx(template=template, context=context)


def get_service_report_directory()->str:
    return "{0}/templates/reports/ServiceReports/".format(current_app.config.get(('REPORT_DIR')))


def get_serviceACL_report_directory()->str:
    return "{0}/templates/reports/ServiceACLReports/".format(current_app.config.get(('REPORT_DIR')))


def get_host_report_directory()->str:
    return "{0}/templates/reports/HostReports/".format(current_app.config.get(('REPORT_DIR')))


def get_host_report_templates()-> list[str]:
    template_dir = get_host_report_directory()
    return os.listdir(template_dir)


def get_registryCheckDict_directory()->str:
    return "{0}/templates/reports/RegistryCheckDictReports/".format(current_app.config.get(('REPORT_DIR')))

def get_ConfigCheck_directory()->str:
    return "{0}/templates/reports/ConfigCheckReports/".format(current_app.config.get(('REPORT_DIR')))


def get_registryCheckDict_report_templates()-> list[str]:
    template_dir = get_registryCheckDict_directory()
    return os.listdir(template_dir)


def get_configCheck_report_templates()-> list[str]:
    template_dir = get_ConfigCheck_directory()
    return os.listdir(template_dir)


def get_group_report_directory()->str:
    return "{0}/templates/reports/GroupReports/".format(current_app.config.get(('REPORT_DIR')))


def get_group_report_templates()-> list[str]:
    template_dir = get_group_report_directory()
    return os.listdir(template_dir)


def get_service_report_templates()-> list[str]:
    template_dir = get_service_report_directory()
    return os.listdir(template_dir)


def get_serviceACL_report_templates()-> list[str]:
    template_dir = get_serviceACL_report_directory()
    return os.listdir(template_dir)

