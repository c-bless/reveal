from flask import render_template, url_for, request, Response
from flask_login import login_required
from sqlalchemy import and_

from reveal.webapp.sysinfo import sysinfo_bp

from reveal.core.models.sysinfo import Host
from reveal.core.models.sysinfo import Service
from reveal.webapp.sysinfo.forms.hosts import HostSearchForm
from reveal.core.export.excel.hosts import generate_hosts_excel
from reveal.core.export.excel.hosts import generate_hosts_excel_brief


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
        host_filter = []
        if form.validate_on_submit():
            hostname = form.Hostname.data
            domain = form.Domain.data
            domainRole = form.DomainRole.data
            osVersion = form.OSVersion.data
            osBuildNumber = form.OSBuildNumber.data
            osName = form.OSName.data
            systemgroup = form.SystemGroup.data
            location = form.Location.data
            label = form.Label.data

            invertHostname = form.InvertHostname.data
            invertDomain = form.InvertDomain.data
            invertDomainRole = form.InvertDomainRole.data
            invertOsVersion = form.InvertOSVersion.data
            invertOsBuildNumber = form.InvertOSBuildNumber.data
            invertOsName = form.InvertOSName.data
            invertSystemgroup = form.InvertSystemGroup.data
            invertLocation = form.InvertLocation.data
            invertLabel = form.InvertLabel.data

            if len(hostname) > 0 :
                if not invertHostname:
                    host_filter.append(Host.Hostname.ilike("%"+hostname+"%"))
                else:
                    host_filter.append(Host.Hostname.notilike("%"+hostname+"%"))
            if len(domain) > 0:
                if not invertDomain:
                    host_filter.append(Host.Domain.ilike("%"+domain+"%"))
                else:
                    host_filter.append(Host.Domain.notilike("%"+domain+"%"))
            if len(domainRole) > 0:
                if not invertDomainRole:
                    host_filter.append(Host.DomainRole.ilike("%"+domainRole+"%"))
                else:
                    host_filter.append(Host.DomainRole.notilike("%"+domainRole+"%"))
            if len(osVersion) > 0:
                if not invertOsVersion:
                    host_filter.append(Host.OSVersion.ilike("%"+osVersion+"%"))
                else:
                    host_filter.append(Host.OSVersion.notilike("%"+osVersion+"%"))
            if len(osBuildNumber) > 0:
                if not invertOsBuildNumber:
                    host_filter.append(Host.OSBuildNumber.ilike("%"+osBuildNumber+"%"))
                else:
                    host_filter.append(Host.OSBuildNumber.notilike("%"+osBuildNumber+"%"))
            if len(osName) > 0:
                if not invertOsName:
                    host_filter.append(Host.OSName.ilike("%"+osName+"%"))
                else:
                    host_filter.append(Host.OSName.notilike("%"+osName+"%"))
            if len(systemgroup) > 0:
                if not invertSystemgroup:
                    host_filter.append(Host.SystemGroup.ilike("%"+systemgroup+"%"))
                else:
                    host_filter.append(Host.SystemGroup.notilike("%"+systemgroup+"%"))
            if len(location) > 0:
                if not invertLocation:
                    host_filter.append(Host.Location.ilike("%"+location+"%"))
                else:
                    host_filter.append(Host.Location.notilike("%"+location+"%"))
            if len(label) > 0:
                if not invertLabel:
                    host_filter.append(Host.Label.ilike("%"+label+"%"))
                else:
                    host_filter.append(Host.Label.notilike("%"+label+"%"))
            hosts = Host.query.filter(and_(*host_filter)).all()

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
