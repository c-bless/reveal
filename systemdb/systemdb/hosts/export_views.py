from flask import render_template, abort, Response, redirect, url_for

from . import host_bp

from ..core.sysinfo_models import Host, Service

import os
from .export_func import template_detail_dir, template_dir
from .export_func import generate_hosts_docx, generate_single_host_docx, generate_hosts_excel, generate_services_excel

@host_bp.route('/hosts/export/templates', methods=['GET'])
def template_list():
    templates = os.listdir(template_dir)
    return render_template('template_list.html', templates=templates, title="Available templates")


@host_bp.route('/hosts/export/word/<template>', methods=['GET'])
def export_hosts_docx(template):
    hosts = Host.query.all()

    if template not in os.listdir(template_dir):
        abort(403, "Unknown template.")

    template_file = "{0}{1}".format(template_dir, template)

    if template_file[-5:] == ".docx":
        output = generate_hosts_docx(template_file, hosts=hosts)
        return Response(output, mimetype="text/docx",
                        headers={"Content-disposition": "attachment; filename=hosts-{0}.docx".format(template)})

    return redirect(url_for('hosts.template_list'))


@host_bp.route('/hosts/export/excel/', methods=['GET'])
def export_hosts_excel():
    hosts = Host.query.all()

    output = generate_hosts_excel(hosts)

    return Response(output, mimetype="text/docx",
                    headers={"Content-disposition": "attachment; filename=hosts.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })

    return redirect(url_for('hosts.host_list'))

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




@host_bp.route('/services/export/excel', methods=['GET'])
def service_export_excel():
    services = Service.query.all()

    output = generate_services_excel(services)

    return Response(output, mimetype="text/docx",
                    headers={"Content-disposition": "attachment; filename=services.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})

    return redirect(url_for('hosts.host_list'))
