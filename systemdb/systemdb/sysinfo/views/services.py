from flask import render_template, url_for, request, Response
from sqlalchemy import desc,and_

from .. import sysinfo_bp

from ...models.sysinfo import Host, Service


@sysinfo_bp.route('/services/', methods=['GET'])
def service_list():
    services = Service.query.all()
    return render_template('service_list.html', services=services)


@sysinfo_bp.route('/services/<int:id>', methods=['GET'])
def service_detail(id):
    service = Service.query.get_or_404(id)
    host = Host.query.get_or_404(service.Host_id)
    permissionStr = service.BinaryPermissionsStr.split("\n")if service.BinaryPermissionsStr is not None else ""
    return render_template("service_details.html", service=service, host=host, binaryPermissionStr=permissionStr)
