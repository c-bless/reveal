from flask import render_template, request, Response
from flask_login import login_required
from sqlalchemy import and_

from reveal.webapp.sysinfo import sysinfo_bp
from reveal.webapp.sysinfo.forms.defender import DefenderSearchForm
from reveal.core.models.sysinfo import Host
from reveal.core.export.excel.hosts import generate_hosts_excel


@sysinfo_bp.route('/defender/search/', methods=['GET', 'POST'])
@login_required
def defender_search_list():
    form = DefenderSearchForm()
    if request.method == 'POST':
        host_filter = []
        if form.validate_on_submit():
            hostname = form.Hostname.data
            domain = form.Domain.data
            osName = form.OSName.data
            systemgroup = form.SystemGroup.data
            location = form.Location.data
            label = form.Label.data

            invertHostname = form.InvertHostname.data
            invertDomain = form.InvertDomain.data
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

            if 'full' in request.form:
                output = generate_hosts_excel(hosts)
                return Response(output, mimetype="text/xslx",
                                headers={"Content-disposition": "attachment; filename=hosts.xlsx",
                                         "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})
        else:

            return render_template('sysinfo/defender/defender_search_list.html', form=form)
    else:
        hosts = Host.query.all()

    return render_template('sysinfo/defender/defender_search_list.html', form=form, hosts=hosts)
