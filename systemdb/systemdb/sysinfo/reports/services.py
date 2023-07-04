from flask import render_template, Response, url_for
from sqlalchemy import and_

from .. import sysinfo_bp
from ..export_func import generate_services_excel

from ...models.sysinfo import Service

from . import ReportInfo
####################################################################
# Hosts with enabled SMBv1
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