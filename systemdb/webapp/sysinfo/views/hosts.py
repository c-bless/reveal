from flask import render_template, url_for, request, Response
from flask_login import login_required
from sqlalchemy import and_

from systemdb.webapp.sysinfo import sysinfo_bp

from systemdb.core.models.sysinfo import Host
from systemdb.core.models.sysinfo import Service
from systemdb.webapp.sysinfo.forms.hosts import HostSearchForm
from systemdb.core.export.excel.hosts import generate_hosts_excel
from systemdb.core.export.excel.hosts import generate_hosts_excel_brief


@sysinfo_bp.route('/hosts/', methods=['GET'])
@login_required
def host_list():
    hosts = Host.query.all()
    return render_template('sysinfo/host/host_list.html', hosts=hosts, download_url=url_for("sysinfo.hosts_export_excel"))


@sysinfo_bp.route('/hosts/search/', methods=['GET', 'POST'])
@login_required
def host_search_list():
    form = HostSearchForm()

    if request.method == 'POST':
        filters = []
        if form.validate_on_submit():
            hostname = form.Hostname.data
            domain = form.Domain.data
            domainRole = form.DomainRole.data
            osVersion = form.OSVersion.data
            osBuildNumber = form.OSBuildNumber.data
            osName = form.OSName.data
            systemgroup = form.SystemGroup.data
            location = form.Location.data

            invertHostname = form.InvertHostname.data
            invertDomain = form.InvertDomain.data
            invertDomainRole = form.InvertDomainRole.data
            invertOsVersion = form.InvertOSVersion.data
            invertOsBuildNumber = form.InvertOSBuildNumber.data
            invertOsName = form.InvertOSName.data
            invertSystemgroup = form.InvertSystemGroup.data
            invertLocation = form.InvertLocation.data

            if len(hostname) > 0 :
                if not invertHostname:
                    filters.append(Host.Hostname.ilike("%"+hostname+"%"))
                else:
                    filters.append(Host.Hostname.notilike("%"+hostname+"%"))
            if len(domain) > 0:
                if not invertDomain:
                    filters.append(Host.Domain.ilike("%"+domain+"%"))
                else:
                    filters.append(Host.Domain.notilike("%"+domain+"%"))
            if len(domainRole) > 0:
                if not invertDomainRole:
                    filters.append(Host.DomainRole.ilike("%"+domainRole+"%"))
                else:
                    filters.append(Host.DomainRole.notilike("%"+domainRole+"%"))
            if len(osVersion) > 0:
                if not invertOsVersion:
                    filters.append(Host.OSVersion.ilike("%"+osVersion+"%"))
                else:
                    filters.append(Host.OSVersion.notilike("%"+osVersion+"%"))
            if len(osBuildNumber) > 0:
                if not invertOsBuildNumber:
                    filters.append(Host.OSBuildNumber.ilike("%"+osBuildNumber+"%"))
                else:
                    filters.append(Host.OSBuildNumber.notilike("%"+osBuildNumber+"%"))
            if len(osName) > 0:
                if not invertOsName:
                    filters.append(Host.OSName.ilike("%"+osName+"%"))
                else:
                    filters.append(Host.OSName.notilike("%"+osName+"%"))
            if len(systemgroup) > 0:
                if not invertSystemgroup:
                    filters.append(Host.SystemGroup.ilike("%"+systemgroup+"%"))
                else:
                    filters.append(Host.SystemGroup.notilike("%"+systemgroup+"%"))
            if len(location) > 0:
                if not invertLocation:
                    filters.append(Host.Location.ilike("%"+location+"%"))
                else:
                    filters.append(Host.Location.notilike("%"+location+"%"))
            hosts = Host.query.filter(and_(*filters)).all()

            if 'brief' in request.form:
                output = generate_hosts_excel_brief(hosts)
                return Response(output, mimetype="text/xslx",
                                headers={"Content-disposition": "attachment; filename=hosts_brief.xlsx",
                                         "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})
            if 'full' in request.form:
                output = generate_hosts_excel(hosts)
                return Response(output, mimetype="text/xslx",
                                headers={"Content-disposition": "attachment; filename=hosts.xlsx",
                                         "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})
        else:

            return render_template('sysinfo/host/host_search_list.html', form=form)
    else:
        hosts = Host.query.all()

    return render_template('sysinfo/host/host_search_list.html', form=form, hosts=hosts)


@sysinfo_bp.route('/hosts/<int:id>', methods=['GET'])
@login_required
def host_detail(id):
    host = Host.query.get_or_404(id)
    return render_template('sysinfo/host/host_details.html', host=host)


@sysinfo_bp.route('/hosts/<int:id>/services/', methods=['GET'])
@login_required
def host_service_list(id):
    services = Service.query.filter(Service.Host_id == id).all()
    return render_template('sysinfo/service/service_list.html', services=services)
