from flask import render_template, request, Response
from flask_login import login_required
from sqlalchemy import and_

from reveal.core.configreview.util import get_configreview_checks, generate_configreview_excel
from reveal.core.configreview.util import load_configreview_checks
from reveal.core.configreview.util import verify_config_checks
from reveal.core.models.sysinfo import Host
from reveal.webapp.sysinfo import sysinfo_bp
from reveal.webapp.sysinfo.forms.configreview import HostConfigReviewSearchForm


@sysinfo_bp.route('/hosts/configreview/search/', methods=['GET', 'POST'])
@login_required
def host_configreview_search_list():
    form = HostConfigReviewSearchForm()

    cc_files = get_configreview_checks()
    form.ConfigReviewFile.choices = [(cc_file, cc_file) for cc_file in cc_files]

    if request.method == 'POST':
        host_filter = []
        if form.validate_on_submit():
            hostname = form.Hostname.data
            domain = form.Domain.data
            osName = form.OSName.data
            systemgroup = form.SystemGroup.data
            location = form.Location.data
            label = form.Label.data
            selectedReview = form.ConfigReviewFile.data

            invertHostname = form.InvertHostname.data
            invertDomain = form.InvertDomain.data
            invertOsName = form.InvertOSName.data
            invertSystemgroup = form.InvertSystemGroup.data
            invertLocation = form.InvertLocation.data
            invertLabel = form.InvertLabel.data

            if len(hostname) > 0:
                if not invertHostname:
                    host_filter.append(Host.Hostname.ilike("%" + hostname + "%"))
                else:
                    host_filter.append(Host.Hostname.notilike("%" + hostname + "%"))
            if len(domain) > 0:
                if not invertDomain:
                    host_filter.append(Host.Domain.ilike("%" + domain + "%"))
                else:
                    host_filter.append(Host.Domain.notilike("%" + domain + "%"))
            if len(osName) > 0:
                if not invertOsName:
                    host_filter.append(Host.OSName.ilike("%" + osName + "%"))
                else:
                    host_filter.append(Host.OSName.notilike("%" + osName + "%"))
            if len(systemgroup) > 0:
                if not invertSystemgroup:
                    host_filter.append(Host.SystemGroup.ilike("%" + systemgroup + "%"))
                else:
                    host_filter.append(Host.SystemGroup.notilike("%" + systemgroup + "%"))
            if len(location) > 0:
                if not invertLocation:
                    host_filter.append(Host.Location.ilike("%" + location + "%"))
                else:
                    host_filter.append(Host.Location.notilike("%" + location + "%"))
            if len(label) > 0:
                if not invertLabel:
                    host_filter.append(Host.Label.ilike("%" + label + "%"))
                else:
                    host_filter.append(Host.Label.notilike("%" + label + "%"))
            hosts = Host.query.filter(and_(*host_filter)).all()

            if 'runReview' in request.form:
                if selectedReview in cc_files:
                    checks = load_configreview_checks(fname=selectedReview)
                    result = verify_config_checks(hosts, checks)
                    output = generate_configreview_excel(results=result.results)
                    return Response(output, mimetype="text/docx",
                                    headers={"Content-disposition": "attachment; filename=pcs7.xlsx",
                                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})

        else:

            return render_template('sysinfo/configreview/host_configreview_search_list.html', form=form)
    else:
        hosts = Host.query.all()

    return render_template('sysinfo/configreview/host_configreview_search_list.html', form=form, hosts=hosts)
