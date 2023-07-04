from flask import render_template, Response, url_for, request
from flask.views import MethodView

from sqlalchemy import and_

from .. import sysinfo_bp
from ..export_func import generate_services_excel

from ...models.sysinfo import Service, ServiceACL
from ..forms.services import ServiceAclSearchForm

from . import ReportInfo
####################################################################
# Hosts with UQSP vulnerabilities
####################################################################
@sysinfo_bp.route('/hosts/report/services/uqsp/', methods=['GET'])
def hosts_report_services_uqsp():
    services = Service.query.filter(and_(Service.PathName.notlike('"%'),
                                         Service.PathName.contains(" "),
                                         Service.PathName.notlike('C:\\Windows%'))).all()

    return render_template('service_list.html', services=services,
                           download_url=url_for("sysinfo.hosts_report_services_uqsp_excel"))


@sysinfo_bp.route('/hosts/report/services/uqsp/excel', methods=['GET'])
def hosts_report_services_uqsp_excel():
    services = Service.query.filter(and_(Service.PathName.notlike('"%'),
                                         Service.PathName.contains(" "),
                                         Service.PathName.notlike('C:\\Windows%'))).all()

    output = generate_services_excel(services=services)
    return Response(output, mimetype="text/xlsx",
                    headers={"Content-disposition": "attachment; filename=usqp.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })



class ReportUQSP(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="UQSP",
            category="Systemhardening",
            tags=["Systemhardening", "Unqouted Service Pathes", "UQSP", "Service Misconfiguration"],
            description='Report all services where the path is not enclosed in quotes and which have a spaces in the path.',
            views=[("view", url_for("sysinfo.hosts_report_services_uqsp"))]
        )

####################################################################
@sysinfo_bp.route('/report/services/by-acl/', methods=['GET', 'POST'])
def hosts_report_services_by_acl():
    form = ServiceAclSearchForm()

    if request.method == 'POST':
        if form.validate_on_submit():
            user = form.User.data
            permission = form.Permission.data
            acls = ServiceACL.query.filter(and_(ServiceACL.AccountName.like("%" + user + "%"),
                                                    ServiceACL.AccessRight.like("%" + permission + "%")
                                                    )).all()
            return render_template('service_search_list.html',
                                   form=form,
                                   acls=acls,
                                   download_url=url_for("sysinfo.hosts_report_services_uqsp_excel"))
        else:
            print("Invlaid input")
            return render_template('service_search_list.html',
                                   form=form,
                                   download_url=url_for("sysinfo.hosts_report_services_uqsp_excel"))
    else:
        return render_template('service_search_list.html',
                               form=form,
                               download_url=url_for("sysinfo.hosts_report_services_uqsp_excel"))

class ReportByPermission(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="Service By ACL",
            category="Systemhardening",
            tags=["Systemhardening", "ACL", "User Permissions"],
            description='Report all services where the ACLs match specified User and Permission.',
            views=[("view", url_for("sysinfo.hosts_report_services_by_acl"))]
        )
