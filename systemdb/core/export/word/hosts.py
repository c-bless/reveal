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


def generate_single_host_docx(template, host=None):
    context = {'host': host}
    return generate_docx(template=template, context=context)