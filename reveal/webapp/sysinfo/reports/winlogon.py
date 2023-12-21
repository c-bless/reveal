from flask import render_template, Response, url_for, request, current_app
from flask_login import login_required

from reveal.webapp.sysinfo import sysinfo_bp
from reveal.core.export.excel.hosts import generate_hosts_excel
from reveal.core.export.excel.hosts import generate_hosts_excel_brief
from reveal.core.export.excel.winlogon import generate_winlogon_excel
from reveal.webapp.sysinfo.forms.report.RegistryReports import WinlogonReportForm
from reveal.core.models.sysinfo import Host
from reveal.core.reports import ReportInfo

from reveal.core.export.word.util import get_host_report_templates
from reveal.core.export.word.util import get_host_report_directory
from reveal.core.export.word.util import generate_hosts_report_docx

from reveal.core.util import decrypt


####################################################################
# Hosts with DefaultPassword in Registry
####################################################################
@sysinfo_bp.route('/report/winlogon', methods=['GET', 'POST'])
@login_required
def hosts_report_winlogon():

    host_filter = []
    host_filter.append(Host.DefaultPassword != "")

    form = WinlogonReportForm()

    templates = get_host_report_templates()
    form.TemplateFile.choices = [(template, template) for template in templates]

    if request.method == 'POST':
        filters = []
        if form.validate_on_submit():
            systemgroup = form.SystemGroup.data
            location = form.Location.data
            selectedTemplate = form.TemplateFile.data
            decrypt_pw = form.Decrypt.data

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

            hosts = Host.query.filter(*host_filter).all()

            key = current_app.config.get("AES_KEY")

            for h in hosts:
                if decrypt_pw:
                    try:
                        h.DefaultPassword = decrypt(cipher_text_b64=h.DefaultPassword, key=key).decode("utf-8")
                    except:
                        pass
                else:
                    h.DefaultPassword = "<REMOVED>"

            if 'brief' in request.form:
                output = generate_hosts_excel_brief(hosts)
                return Response(output, mimetype="text/docx",
                                headers={"Content-disposition": "attachment; filename=hosts-with-winlogon-brief.xlsx",
                                         "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})
            if 'full' in request.form:
                output = generate_hosts_excel(hosts)
                return Response(output, mimetype="text/docx",
                                headers={"Content-disposition": "attachment; filename=hosts-with-winlogon-full.xlsx",
                                         "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})
            if 'winlogon' in request.form:
                output = generate_winlogon_excel(hosts)
                return Response(output, mimetype="text/docx",
                                headers={"Content-disposition": "attachment; filename=hosts-with-winlogon-values.xlsx",
                                         "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})
            if 'word' in request.form:
                if selectedTemplate in templates:
                    template_dir = get_host_report_directory()
                    report = ReportPWInWinlogon()
                    output = generate_hosts_report_docx(f"{template_dir}/{selectedTemplate}", report, hosts=hosts)
                    return Response(output, mimetype="text/docx",
                                    headers={"Content-disposition": "attachment; filename={0}.docx".format(report.name)})
    else:
        hosts = Host.query.filter(*host_filter).all()

    return render_template('sysinfo/reports/host_with_winlogon.html', hosts=hosts, form=form,
                           report_name="Password in Winlogon")


class ReportPWInWinlogon(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="Password in Winlogon",
            category="Systemhardening",
            tags=["Cleartext password", "Missconfigured Autologon", "Winlogon", "Registry"],
            description='Report all hosts where a password is stored in clear text in Windows Registry',
            views=[("view", url_for("sysinfo.hosts_report_winlogon"))]
        )