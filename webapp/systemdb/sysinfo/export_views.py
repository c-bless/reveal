from flask import render_template, abort, Response, redirect, url_for
from flask_login import login_required

from webapp.systemdb.sysinfo import sysinfo_bp

from webapp.systemdb.models.sysinfo import Host, Service, Product

import os
from webapp.systemdb.sysinfo.export_func import template_detail_dir, template_dir
from webapp.systemdb.sysinfo.export_func import generate_hosts_docx, generate_single_host_docx, generate_hosts_excel, \
    generate_services_excel, generate_hosts_excel_brief
from webapp.systemdb.sysinfo.export_func import generate_products_excel


@sysinfo_bp.route('/export/templates', methods=['GET'])
@login_required
def template_list():
    templates = os.listdir(template_dir)
    return render_template('template_list.html', templates=templates, title="Available templates")


@sysinfo_bp.route('/hosts/export/word/<template>', methods=['GET'])
@login_required
def hosts_export_docx(template):
    hosts = Host.query.all()
    if template not in os.listdir(template_dir):
        abort(403, "Unknown template.")
    template_file = "{0}{1}".format(template_dir, template)
    if template_file[-5:] == ".docx":
        output = generate_hosts_docx(template_file, hosts=hosts)
        return Response(output, mimetype="text/docx",
                        headers={"Content-disposition": "attachment; filename=hosts-{0}.docx".format(template)})
    return redirect(url_for('sysinfo.template_list'))


@sysinfo_bp.route('/hosts/export/excel/', methods=['GET'])
@login_required
def hosts_export_excel():
    hosts = Host.query.all()
    output = generate_hosts_excel(hosts)
    return Response(output, mimetype="text/xslx",
                    headers={"Content-disposition": "attachment; filename=hosts.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })


@sysinfo_bp.route('/hosts/export/excel/brief', methods=['GET'])
@login_required
def hosts_export_excel_brief():
    hosts = Host.query.all()
    output = generate_hosts_excel_brief(hosts)
    return Response(output, mimetype="text/xslx",
                    headers={"Content-disposition": "attachment; filename=hosts_brief.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })


@sysinfo_bp.route('/hosts/<int:id>/export/word', methods=['GET'])
@login_required
def host_export_word(id):
    host = Host.query.get_or_404(id)
    template = "host_detail_template.docx"
    if template not in os.listdir(template_detail_dir):
        abort(403, "Unknown template.")
    template_file = "{0}{1}".format(template_detail_dir, template)
    if template_file[-5:] == ".docx":
        output = generate_single_host_docx(template_file, host=host)
        return Response(output, mimetype="text/docx",
                        headers={"Content-disposition": "attachment; filename=host-{0}.docx".format(host.Hostname)})

    return redirect(url_for('sysinfo.host_detail',id=id))


@sysinfo_bp.route('/services/export/excel', methods=['GET'])
@login_required
def service_export_excel():
    services = Service.query.all()
    output = generate_services_excel(services)
    return Response(output, mimetype="text/xslx",
                    headers={"Content-disposition": "attachment; filename=services.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})



@sysinfo_bp.route('/products/export/excel', methods=['GET'])
@login_required
def product_export_excel():
    products = Product.query.all()
    output = generate_products_excel(products)
    return Response(output, mimetype="text/xslx",
                    headers={"Content-disposition": "attachment; filename=products.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})

