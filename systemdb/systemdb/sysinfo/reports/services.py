from flask import render_template, Response, url_for
from sqlalchemy import and_

from .. import sysinfo_bp
from ..export_func import generate_services_excel

from ...models.sysinfo import Service


####################################################################
# Hosts with enabled SMBv1
####################################################################
@sysinfo_bp.route('/hosts/report/services/uqsp/', methods=['GET'])
def hosts_report_services_uqsp():
    services = Service.query.filter(and_(Service.PathName.notlike('"%'),
                                         Service.PathName.contains(" "),
                                         Service.PathName.notlike('C:\\Windows%'))).all()

    return render_template('service_list.html', services=services,
                           download_brief_url=url_for("sysinfo.hosts_report_smbv1_excel_brief"),
                           download_url=url_for("sysinfo.hosts_report_smbv1_excel_full"))

