from flask import render_template, Response, url_for,request
from flask_login import login_required
from sqlalchemy import and_
from systemdb.webapp.sysinfo import sysinfo_bp
from systemdb.core.export.excel.powershell import generate_ps2_installed

from systemdb.core.models.sysinfo import Host
from systemdb.core.reports import ReportInfo

from systemdb.webapp.sysinfo.forms.report.PS2Report import PS2ReportForm

from systemdb.core.export.word.util import get_host_report_templates
from systemdb.core.export.word.util import get_host_report_directory
from systemdb.core.export.word.util import generate_hosts_report_docx


####################################################################
# Hosts with PowerShell 2.0 installed
####################################################################
@sysinfo_bp.route('/report/ps2', methods=['GET', 'POST'])
@login_required
def hosts_report_ps2():
    form = PS2ReportForm()

    host_filter = []
    host_filter.append(Host.PS2Installed == True)

    templates = get_host_report_templates()
    form.TemplateFile.choices = [(template, template) for template in templates]

    if request.method == 'POST':

        if form.validate_on_submit():
            systemgroup = form.SystemGroup.data
            location = form.Location.data
            selectedTemplate = form.TemplateFile.data

            invertSystemgroup = form.InvertSystemGroup.data
            invertLocation = form.InvertLocation.data

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

            hosts = Host.query.filter(and_(*host_filter)).all()

            if 'excel' in request.form:
                output = generate_ps2_installed(hosts=hosts)
                return Response(output, mimetype="text/docx",
                                headers={"Content-disposition": "attachment; filename=hosts-with-ps2.xlsx",
                                         "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})
            if 'word' in request.form:
                if selectedTemplate in templates:
                    template_dir = get_host_report_directory()
                    report = ReportPS2Istalled()
                    output = generate_hosts_report_docx(f"{template_dir}/{selectedTemplate}", report, hosts=hosts)
                    return Response(output, mimetype="text/docx",
                                    headers={"Content-disposition": "attachment; filename={0}.docx".format(report.name)})

    else:
        hosts = Host.query.filter(and_(*host_filter)).all()
    return render_template('sysinfo/reports/PS2_list.html', hosts=hosts, form=form,
                           report_name="PowerShell 2.0 Enabled")


class ReportPS2Istalled(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="PowerShell 2.0 Enabled",
            category="Hardening",
            tags=["Powershell", "Systemhardening", "Missing Security Feature", "BSI: SiSyPHus Win10"],
            description='Report all hosts where PowerShell Version 2.0 is installed / enabled.',
            views=[('view', url_for('sysinfo.hosts_report_ps2'))]
        )