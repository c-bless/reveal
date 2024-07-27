from flask import render_template, Response, url_for, request
from flask_login import login_required
from sqlalchemy import and_

from reveal.webapp.sysinfo import sysinfo_bp
from reveal.core.export.excel.hosts import generate_hosts_excel
from reveal.core.export.excel.hosts import generate_hosts_excel_brief
from reveal.core.models.sysinfo import Host
from reveal.core.reports import ReportInfo
from reveal.core.querries.smb import find_hosts_smb_client_signing_disabled
from reveal.core.querries.smb import find_hosts_smb_server_signing_disabled
from reveal.webapp.sysinfo.forms.report.SMBv1Report import SMBv1ReportForm

from reveal.core.export.word.util import get_host_report_templates
from reveal.core.export.word.util import get_host_report_directory
from reveal.core.export.word.util import generate_hosts_report_docx


####################################################################
# Hosts with enabled SMBv1
####################################################################
@sysinfo_bp.route('/report/smb/v1', methods=['GET', 'POST'])
@login_required
def hosts_report_smbv1():
    form = SMBv1ReportForm()

    host_filter = []
    host_filter.append(Host.SMBv1Enabled == True)
    hosts = []

    templates = get_host_report_templates()
    form.TemplateFile.choices = [(template, template) for template in templates]

    if request.method == 'POST':

        if form.validate_on_submit():
            systemgroup = form.SystemGroup.data
            location = form.Location.data
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

            hosts = Host.query.filter(and_(*host_filter)).all()

            if 'brief' in request.form:
                output = generate_hosts_excel_brief(hosts)
                return Response(output, mimetype="text/xlsx",
                                headers={
                                    "Content-disposition": "attachment; filename=hosts-with-smbv1-brief.xlsx",
                                    "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                                })
            if 'full' in request.form:
                output = generate_hosts_excel(hosts)
                return Response(output, mimetype="text/xlsx",
                                headers={
                                    "Content-disposition": "attachment; filename=hosts-with-smbv1-full.xlsx",
                                    "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                                })
            if 'word' in request.form:
                if selectedTemplate in templates:
                    template_dir = get_host_report_directory()
                    report = ReportSMBv1()
                    output = generate_hosts_report_docx(f"{template_dir}/{selectedTemplate}",
                                                        report, hosts=hosts)
                    return Response(output, mimetype="text/docx",
                                    headers={
                                        "Content-disposition": "attachment; filename={0}.docx".format(report.name)
                                    })
    else:
        hosts = Host.query.filter(and_(*host_filter)).all()
    return render_template('sysinfo/reports/host_report_list.html', hosts=hosts, form=form,
                           report_name="SMBv1 Enabled")


class ReportSMBv1(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="SMBv1 Enabled",
            category="Systemhardening",
            tags=["Systemhardening", "SMB", "SMBv1"],
            description='Report all hosts where SMBv1 is installed / enabled.',
            views=[("view", url_for("sysinfo.hosts_report_smbv1"))]
        )


####################################################################
# Hosts where SMB signing is not required
####################################################################
@sysinfo_bp.route('/report/smb/client/nosigning', methods=['GET', 'POST'])
@login_required
def hosts_report_smb_client_nosigning():
    form = SMBv1ReportForm()

    host_filter = []

    templates = get_host_report_templates()
    form.TemplateFile.choices = [(template, template) for template in templates]

    if request.method == 'POST':

        if form.validate_on_submit():
            systemgroup = form.SystemGroup.data
            location = form.Location.data
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
                    host_filter.append(Host.Label.ilike("%" + label + "%"))
                else:
                    host_filter.append(Host.Label.notilike("%" + label + "%"))

            hosts = find_hosts_smb_client_signing_disabled(host_filter=host_filter)

            if 'brief' in request.form:
                output = generate_hosts_excel_brief(hosts)
                return Response(output, mimetype="text/xlsx",
                                headers={
                                    "Content-disposition": "attachment; filename=hosts-no-smb-sign-client-brief.xlsx",
                                    "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                                })
            if 'full' in request.form:
                output = generate_hosts_excel(hosts)
                return Response(output, mimetype="text/xlsx",
                                headers={
                                    "Content-disposition": "attachment; filename=hosts-no-smb-sign-client-full.xlsx",
                                    "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                                })
            if 'word' in request.form:
                if selectedTemplate in templates:
                    template_dir = get_host_report_directory()
                    report = ReportSMBv1()
                    output = generate_hosts_report_docx(f"{template_dir}/{selectedTemplate}",
                                                        report, hosts=hosts)
                    return Response(output, mimetype="text/docx",
                                    headers={
                                        "Content-disposition": "attachment; filename={0}.docx".format(report.name)
                                    })
    else:
        hosts = []
    return render_template('sysinfo/reports/host_report_list.html', hosts=hosts, form=form,
                           report_name="SMB signing not required (client)")


class ReportSMBClientNoSigning(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="SMB signing not required (client)",
            category="Systemhardening",
            tags=["Systemhardening", "SMB", "SMB signing", "SMB client"],
            description='Report all hosts where SMB signing is not required (client)',
            views=[("view", url_for("sysinfo.hosts_report_smb_client_nosigning"))]
        )


####################################################################
# Hosts where SMB signing is not required
####################################################################
@sysinfo_bp.route('/report/smb/server/nosigning', methods=['GET', 'POST'])
@login_required
def hosts_report_smb_server_nosigning():
    form = SMBv1ReportForm()

    host_filter = []
    hosts = []

    templates = get_host_report_templates()
    form.TemplateFile.choices = [(template, template) for template in templates]

    if request.method == 'POST':

        if form.validate_on_submit():
            systemgroup = form.SystemGroup.data
            location = form.Location.data
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

            hosts = find_hosts_smb_server_signing_disabled(host_filter=host_filter)

            if 'brief' in request.form:
                output = generate_hosts_excel_brief(hosts)
                return Response(output, mimetype="text/xlsx",
                                headers={
                                    "Content-disposition": "attachment; filename=hosts-no-smb-sign-server-brief.xlsx",
                                    "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                                })
            if 'full' in request.form:
                output = generate_hosts_excel(hosts)
                return Response(output, mimetype="text/xlsx",
                                headers={
                                    "Content-disposition": "attachment; filename=hosts-no-smb-sign-server-full.xlsx",
                                    "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                                })
            if 'word' in request.form:
                if selectedTemplate in templates:
                    template_dir = get_host_report_directory()
                    report = ReportSMBServerNoSigning()
                    output = generate_hosts_report_docx(f"{template_dir}/{selectedTemplate}",
                                                        report, hosts=hosts)
                    return Response(output, mimetype="text/docx",
                                    headers={
                                        "Content-disposition": "attachment; filename={0}.docx".format(report.name)
                                    })
    return render_template('sysinfo/reports/host_report_list.html', hosts=hosts, form=form,
                           report_name="SMB signing not required (server)")


class ReportSMBServerNoSigning(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="SMB signing not required (server)",
            category="Systemhardening",
            tags=["Systemhardening", "SMB", "SMB signing", "SMB server"],
            description='Report all hosts where SMB signing is not required (server).',
            views=[("view", url_for("sysinfo.hosts_report_smb_server_nosigning"))]
        )