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


def generate_group_report_docx(template, report, groups=[]):
    context = {'groups': groups, 'report': report}
    return generate_docx(template=template, context=context)
