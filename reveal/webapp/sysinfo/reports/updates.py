import datetime
from flask import render_template, Response, url_for, request
from flask_login import login_required


from reveal.core.models.sysinfo import Host
from reveal.core.querries.updates import get_EoLInfo

from reveal.webapp.sysinfo import sysinfo_bp
from reveal.core.export.excel.hosts import generate_hosts_excel
from reveal.core.export.excel.hosts import generate_hosts_excel_brief
from reveal.core.export.excel.eol import generate_eol_excel_brief
from reveal.core.export.excel.eol import generate_eol_excel_full
from reveal.webapp.sysinfo.forms.report.UpdateReports import EOLReportForm
from reveal.webapp.sysinfo.forms.report.UpdateReports import LastUpdateReportForm

from reveal.core.reports import ReportInfo

from reveal.core.export.word.util import get_host_report_templates
from reveal.core.export.word.util import get_host_report_directory
from reveal.core.export.word.util import generate_hosts_report_docx


####################################################################
# Hosts where last update has been installed for more that xxx days
####################################################################
@sysinfo_bp.route('/report/lastupdate/', methods=['GET', 'POST'])
@login_required
def hosts_report_lastupdate():

    host_filter = []

    form = LastUpdateReportForm()

    templates = get_host_report_templates()
    form.TemplateFile.choices = [(template, template) for template in templates]

    if request.method == 'POST':
        if form.validate_on_submit():
            systemgroup = form.SystemGroup.data
            location = form.Location.data
            nDays = form.Days.data
            selectedTemplate = form.TemplateFile.data
            label = form.Label.data

            invertSystemgroup = form.InvertSystemGroup.data
            invertLocation = form.InvertLocation.data
            invertLabel = form.InvertLabel.data

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
                    host_filter.append(Host.Label.ilike("%"+label+"%"))
                else:
                    host_filter.append(Host.Label.notilike("%"+label+"%"))

            if nDays > 0:
                now = datetime.datetime.now()
                delta = now - datetime.timedelta(days=nDays)
                host_filter.append(Host.LastUpdate <= delta)

            hosts = Host.query.filter(*host_filter).all()

            if 'brief' in request.form:
                output = generate_hosts_excel_brief(hosts)
                return Response(output, mimetype="text/docx",
                                headers={"Content-disposition": "attachment; filename=hosts-with-lastupdate-brief.xlsx",
                                         "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})
            if 'full' in request.form:
                output = generate_hosts_excel(hosts)
                return Response(output, mimetype="text/docx",
                                headers={"Content-disposition": "attachment; filename=hosts-with-lastupdate-full.xlsx",
                                         "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})
            if 'word' in request.form:
                if selectedTemplate in templates:
                    template_dir = get_host_report_directory()
                    report = ReportLastUpdate()
                    output = generate_hosts_report_docx(f"{template_dir}/{selectedTemplate}", report, hosts=hosts)
                    return Response(output, mimetype="text/docx",
                                    headers={"Content-disposition": "attachment; filename={0}.docx".format(report.name)})
    else:
        hosts = []

    return render_template('sysinfo/reports/last_update_list.html', hosts=hosts, form=form,
                           report_name='Last update (more than "n" days)')


class ReportLastUpdate(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="Last update",
            category="Patch Management",
            tags=["Updates", "Missing Patches", "Windows Updates", "Patch Management"],
            description='Report all hosts where the last update was installed more that "n" days ago.',
            views=[("view", url_for("sysinfo.hosts_report_lastupdate" ) )]
        )


####################################################################
# List OS and matching hosts that reached the end of life
####################################################################

@sysinfo_bp.route('/hosts/report/eol/', methods=['GET', 'POST'])
@login_required
def hosts_report_eol():
    host_filter = []

    form = EOLReportForm()

    if request.method == 'POST':
        filters = []
        if form.validate_on_submit():
            systemgroup = form.SystemGroup.data
            location = form.Location.data
            label = form.Label.data

            invertSystemgroup = form.InvertSystemGroup.data
            invertLocation = form.InvertLocation.data
            invertLabel = form.InvertLabel.data

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
                    host_filter.append(Host.Label.ilike("%"+label+"%"))
                else:
                    host_filter.append(Host.Label.notilike("%"+label+"%"))

            eol_matches = get_EoLInfo(host_filter=host_filter)

            if 'brief' in request.form:
                output = generate_eol_excel_brief(eol_matches=eol_matches)
                return Response(output, mimetype="text/docx",
                                headers={"Content-disposition": "attachment; filename=eol-systems-brief.xlsx",
                                         "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})
            if 'full' in request.form:
                output = generate_eol_excel_full(eol_matches=eol_matches)
                return Response(output, mimetype="text/docx",
                                headers={"Content-disposition": "attachment; filename=eol-systems-full.xlsx",
                                         "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})
    else:
        eol_matches = get_EoLInfo(host_filter=host_filter)
    return render_template('sysinfo/reports/eol_list.html', eol_matches=eol_matches, form=form,
                           report_name="End-Of-Life - OS")


class ReportEOL(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="End-Of-Life - OS",
            category="Lifecycle Management",
            tags=["End-Of-Life", "EoL", "End-Of-Support", "Lifecycle Management", "Outdated OS"],
            description='Report all hosts which reached the End-of-Life / End-of-Support',
            views=[("view", url_for("sysinfo.hosts_report_eol"))]
        )