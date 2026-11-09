from flask import render_template, Response, url_for, request
from flask_login import login_required

from reveal.webapp.sysinfo import sysinfo_bp
from reveal.core.models.sysinfo import Host
from reveal.core.reports import ReportInfo
from reveal.core.querries import defender as defender_queries
from reveal.core.export.excel.hosts import generate_hosts_excel
from reveal.core.export.excel.hosts import generate_hosts_excel_brief
from reveal.core.export.excel.defender import generate_defender_protection_excel
from reveal.core.export.excel.defender import generate_defender_exclusions_excel
from reveal.core.export.word.util import get_host_report_templates
from reveal.core.export.word.util import get_host_report_directory
from reveal.core.export.word.util import generate_hosts_report_docx
from reveal.webapp.sysinfo.forms.report.DefenderReport import DefenderReportForm

XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


def host_filter_from_report_form(form) -> list:
    """ SystemGroup / Location / Label filter of a report form (RevealReportSearchForm) """
    host_filter = []
    for field, invert in (("SystemGroup", "InvertSystemGroup"), ("Location", "InvertLocation"), ("Label", "InvertLabel")):
        value = (getattr(form, field).data or "").strip()
        if value:
            column = getattr(Host, field)
            pattern = "%" + value + "%"
            host_filter.append(column.notilike(pattern) if getattr(form, invert).data else column.ilike(pattern))
    return host_filter


def _excel_response(output, filename):
    return Response(output, mimetype=XLSX, headers={"Content-disposition": f"attachment; filename={filename}.xlsx",
                                                    "Content-type": XLSX})


def defender_report(report, find_hosts, template, filename, excel_details=None):
    """
    Common handling of the Defender reports: filter form, exports (Excel brief / full / Defender details, Word) and
    result list.

    :param report: ReportInfo of the report (name for the page and the Word export)
    :param find_hosts: function(host_filter) -> list of hosts
    :param template: template of the result list
    :param filename: base name of the exported files
    :param excel_details: function(hosts, status_by_host, settings_by_host) -> Excel file with the Defender details
    """
    form = DefenderReportForm()
    templates = get_host_report_templates()
    form.TemplateFile.choices = [(t, t) for t in templates]
    if not excel_details:
        del form.excel    # no Defender details export for this report (button is not shown)
    host_filter = []

    if request.method == 'POST':
        if form.validate_on_submit():
            host_filter = host_filter_from_report_form(form)
            hosts = find_hosts(host_filter=host_filter)
            if 'brief' in request.form:
                return _excel_response(generate_hosts_excel_brief(hosts), f"{filename}-brief")
            if 'full' in request.form:
                return _excel_response(generate_hosts_excel(hosts), f"{filename}-full")
            if 'excel' in request.form and excel_details:
                status_by_host, settings_by_host = defender_queries.get_defender_data(hosts)
                return _excel_response(excel_details(hosts, status_by_host, settings_by_host), f"{filename}-defender")
            if 'word' in request.form and form.TemplateFile.data in templates:
                output = generate_hosts_report_docx(f"{get_host_report_directory()}/{form.TemplateFile.data}",
                                                    report, hosts=hosts)
                return Response(output, mimetype="text/docx",
                                headers={"Content-disposition": "attachment; filename={0}.docx".format(report.name)})
        else:
            hosts = []
    else:
        hosts = find_hosts(host_filter=host_filter)

    status_by_host, settings_by_host = defender_queries.get_defender_data(hosts)
    return render_template(template, hosts=hosts, form=form, report_name=report.name, excel_details=bool(excel_details),
                           status_by_host=status_by_host, settings_by_host=settings_by_host,
                           disabled_components=defender_queries.disabled_components)


####################################################################
# Hosts with disabled Defender protection components
####################################################################
@sysinfo_bp.route('/report/defender/protection-disabled/', methods=['GET', 'POST'])
@login_required
def hosts_report_defender_protection_disabled():
    return defender_report(ReportDefenderProtectionDisabled(), defender_queries.find_hosts_protection_disabled,
                           'sysinfo/reports/defender_protection_list.html', "defender-protection-disabled",
                           excel_details=lambda hosts, status, settings: generate_defender_protection_excel(hosts, status))


class ReportDefenderProtectionDisabled(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="Defender protection disabled",
            category="Systemhardening",
            tags=["Systemhardening", "Defender", "Antivirus", "Malware Protection"],
            description='Report all hosts where at least one protection component of Microsoft Defender is disabled '
                        '(real-time protection, antivirus, Defender service, behavior monitoring, download scanning, '
                        'on-access protection, network inspection).',
            views=[("view", url_for("sysinfo.hosts_report_defender_protection_disabled"))]
        )


####################################################################
# Hosts with Defender exclusions
####################################################################
@sysinfo_bp.route('/report/defender/exclusions/', methods=['GET', 'POST'])
@login_required
def hosts_report_defender_exclusions():
    return defender_report(ReportDefenderExclusions(), defender_queries.find_hosts_with_exclusions,
                           'sysinfo/reports/defender_exclusions_list.html', "defender-exclusions",
                           excel_details=lambda hosts, status, settings: generate_defender_exclusions_excel(hosts, settings))


class ReportDefenderExclusions(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="Defender exclusions configured",
            category="Systemhardening",
            tags=["Systemhardening", "Defender", "Antivirus", "Exclusions"],
            description='Report all hosts with configured Microsoft Defender exclusions (paths / processes). '
                        'Exclusions are not scanned and are a common way to hide malware.',
            views=[("view", url_for("sysinfo.hosts_report_defender_exclusions"))]
        )


####################################################################
# Hosts without Defender information
####################################################################
@sysinfo_bp.route('/report/defender/no-data/', methods=['GET', 'POST'])
@login_required
def hosts_report_defender_no_data():
    return defender_report(ReportDefenderNoData(), defender_queries.find_hosts_without_defender_data,
                           'sysinfo/reports/host_report_list.html', "hosts-without-defender-data")


class ReportDefenderNoData(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="Hosts without Defender information",
            category="Systemhardening",
            tags=["Systemhardening", "Defender", "Antivirus"],
            description='Report all hosts without collected Microsoft Defender information (e.g. third-party '
                        'antivirus, Defender not installed or not collected). The malware protection of these hosts '
                        'has to be reviewed separately.',
            views=[("view", url_for("sysinfo.hosts_report_defender_no_data"))]
        )
