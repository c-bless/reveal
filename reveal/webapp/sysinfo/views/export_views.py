import os

from flask import render_template
from flask import abort
from flask import Response
from flask import redirect
from flask import url_for
from flask import current_app

from flask_login import login_required

from reveal.webapp.sysinfo import sysinfo_bp

from reveal.core.models.sysinfo import Host, Service, Product, Share
from reveal.core.vars import REPORT_TYPES_WORD

from reveal.core.export.word.util import generate_hosts_docx
from reveal.core.export.word.util import generate_single_host_docx

from reveal.core.export.excel.hosts import generate_hosts_excel
from reveal.core.export.excel.hosts import generate_hosts_excel_brief
from reveal.core.export.excel.services import generate_services_excel
from reveal.core.export.excel.shares import  generate_shares_excel
from reveal.core.export.excel.products import generate_products_excel


@sysinfo_bp.route('/export/hosts/templates', methods=['GET'])
@login_required
def template_list_hosts():
    template_dir = "{0}/templates/hosts/".format(current_app.config.get(('REPORT_DIR')))
    templates = os.listdir(template_dir)
    return render_template('sysinfo/template_list.html', templates=templates, title="Available templates")


@sysinfo_bp.route('/hosts/export/word/<template>', methods=['GET'])
@login_required
def hosts_export_docx(template):
    hosts = Host.query.all()
    template_dir = "{0}/templates/hosts/".format(current_app.config.get(('REPORT_DIR')))
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
    template_detail_dir = "{0}/templates/details/".format(current_app.config.get(('REPORT_DIR')))
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



@sysinfo_bp.route('/shares/export/excel', methods=['GET'])
@login_required
def share_export_excel():
    shares = Share.query.all()
    output = generate_shares_excel(shares=shares)
    return Response(output, mimetype="text/xslx",
                    headers={"Content-disposition": "attachment; filename=shares.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})
