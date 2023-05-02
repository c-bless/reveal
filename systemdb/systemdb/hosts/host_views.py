from flask import render_template, abort, Response, redirect, url_for

import os
from docxtpl import DocxTemplate, RichText
from io import StringIO, BytesIO

from ..core.model import Host

from . import host_bp



basedir = os.path.abspath(os.path.join(os.path.dirname(__file__),"../../.."))
template_dir = "{0}/reports/templates/hosts/".format(basedir)
report_dir = "{0}/reports/outdir/".format(basedir)


@host_bp.route('/hosts/', methods=['GET'])
def host_list():
    hosts = Host.query.all()
    return render_template('host_list.html', hosts=hosts)

@host_bp.route('/hosts/<int:id>', methods=['GET'])
def host_detail(id):
    host = Host.query.get_or_404(id)
    return render_template('host_details.html', host=host)

@host_bp.route('/hosts/export/templates', methods=['GET'])
def template_list():
    templates = os.listdir(template_dir)
    return render_template('template_list.html', templates=templates, title="Available templates")

def generate_docx(template, hosts=[]):
    doc = DocxTemplate(template)
    context = {'hosts': hosts}
    doc.render(context)
    f = BytesIO()
    doc.save(f)
    length = f.tell()
    f.seek(0)
    return f

@host_bp.route('/hosts/export/<template>', methods=['GET'])
def export(template):
    hosts = Host.query.all()

    if template not in os.listdir(template_dir):
        abort(403, "Unknown template.")

    template_file = "{0}{1}".format(template_dir, template)

    if template_file[-5:] == ".docx":
        output = generate_docx(template_file, hosts=hosts)
        return Response(output, mimetype="text/docx",
                        headers={"Content-disposition": "attachment; filename=hosts-{0}.docx".format(template)})

    return redirect(url_for('hosts.template_list'))