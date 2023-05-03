from flask import render_template, abort, Response, redirect, url_for

import os
from docxtpl import DocxTemplate, RichText
from io import StringIO, BytesIO

from ..core.model import Host, Group, User, Service, Product, Share

from . import host_bp



basedir = os.path.abspath(os.path.join(os.path.dirname(__file__),"../../.."))
template_dir = "{0}/reports/templates/hosts/".format(basedir)
template_detail_dir = "{0}/reports/templates/details/".format(basedir)
report_dir = "{0}/reports/outdir/".format(basedir)


@host_bp.route('/hosts/', methods=['GET'])
def host_list():
    hosts = Host.query.all()
    return render_template('host_list.html', hosts=hosts)

@host_bp.route('/hosts/<int:id>', methods=['GET'])
def host_detail(id):
    host = Host.query.get_or_404(id)
    return render_template('host_details.html', host=host)

@host_bp.route('/groups/<int:id>', methods=['GET'])
def group_detail(id):
    group = Group.query.get_or_404(id)
    host = Host.query.get_or_404(group.Host_id)
    return render_template("group_details.html", group=group, host=host)

@host_bp.route('/users/<int:id>', methods=['GET'])
def user_detail(id):
    user = User.query.get_or_404(id)
    host = Host.query.get_or_404(user.Host_id)
    return render_template("user_details.html", user=user, host=host)


@host_bp.route('/services/<int:id>', methods=['GET'])
def service_detail(id):
    service = Service.query.get_or_404(id)
    host = Host.query.get_or_404(service.Host_id)
    permissions = service.BinaryPermissions.split("\n")
    return render_template("service_details.html", service=service, host=host, binaryPermissions=permissions)


@host_bp.route('/shares/<int:id>', methods=['GET'])
def share_detail(id):
    share = Share.query.get_or_404(id)
    host = Host.query.get_or_404(share.Host_id)
    ntfs_permissions = share.NTFSPermission.split("\n")
    share_permissions = share.SharePermission.split("\n")
    return render_template("share_details.html", share=share, host=host, ntfs_permissions=ntfs_permissions, share_permissions=share_permissions)

@host_bp.route('/hosts/export/templates', methods=['GET'])
def template_list():
    templates = os.listdir(template_dir)
    return render_template('template_list.html', templates=templates, title="Available templates")


def generate_hosts_docx(template, hosts=[]):
    doc = DocxTemplate(template)
    context = {'hosts': hosts}
    doc.render(context)
    f = BytesIO()
    doc.save(f)
    length = f.tell()
    f.seek(0)
    return f


def generate_single_host_docx(template, host=None):
    doc = DocxTemplate(template)
    context = {'host': host}
    doc.render(context)
    f = BytesIO()
    doc.save(f)
    length = f.tell()
    f.seek(0)
    return f

@host_bp.route('/hosts/export/<template>', methods=['GET'])
def export_hosts(template):
    hosts = Host.query.all()

    if template not in os.listdir(template_dir):
        abort(403, "Unknown template.")

    template_file = "{0}{1}".format(template_dir, template)

    if template_file[-5:] == ".docx":
        output = generate_hosts_docx(template_file, hosts=hosts)
        return Response(output, mimetype="text/docx",
                        headers={"Content-disposition": "attachment; filename=hosts-{0}.docx".format(template)})

    return redirect(url_for('hosts.template_list'))

@host_bp.route('/hosts/<int:id>/export/', methods=['GET'])
def export_host(id):
    host = Host.query.get_or_404(id)
    template = "host_detail_template.docx"
    if template not in os.listdir(template_detail_dir):
        abort(403, "Unknown template.")

    template_file = "{0}{1}".format(template_detail_dir, template)

    if template_file[-5:] == ".docx":
        output = generate_single_host_docx(template_file, host=host)
        return Response(output, mimetype="text/docx",
                        headers={"Content-disposition": "attachment; filename=host-{0}.docx".format(host.Hostname)})

    return redirect(url_for('hosts.host_detail',id=id))