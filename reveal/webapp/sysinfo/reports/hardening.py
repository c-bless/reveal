from flask import render_template, Response, url_for, request
from flask_login import login_required

from reveal.webapp.sysinfo import sysinfo_bp
from reveal.core.querries.hardening import find_hotkeys_enabled_dict
from reveal.core.querries.hardening import find_hotkeys_enabled_list
from reveal.core.querries.hardening import find_hosts_with_LLMNR

from reveal.core.export.excel.checks import generate_registrychecks_excel
from reveal.core.export.excel.checks import generate_configchecks_excel
from reveal.core.models.sysinfo import Host
from reveal.webapp.sysinfo.forms.report.ChecksReport import RegistryCheckReportForm
from reveal.webapp.sysinfo.forms.report.ChecksReport import ConfigCheckReportForm

from reveal.core.export.word.util import get_registryCheckDict_report_templates
from reveal.core.export.word.util import get_configCheck_report_templates
from reveal.core.export.word.util import get_registryCheckDict_directory
from reveal.core.export.word.util import get_ConfigCheck_directory
from reveal.core.reports import ReportInfo

from reveal.core.export.word.util import generate_hotkey_docx
from reveal.core.export.word.util import generate_configcheck_docx


####################################################################
# None Disabled Hotkeys and corresponding hosts
####################################################################
@sysinfo_bp.route('/report/hotkeys/', methods=['GET', 'POST'])
@login_required
def report_hotkeys_enabled():
    form = RegistryCheckReportForm()
    host_filter = []

    templates = get_registryCheckDict_report_templates()
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

            if 'excel' in request.form:
                hotkeys = find_hotkeys_enabled_list(host_filter=host_filter)
                output = generate_registrychecks_excel(hotkeys)
                return Response(output, mimetype="text/xlsx",
                                headers={"Content-disposition": "attachment; filename=missing-disabled-hostkeys.xlsx",
                                         "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})

            hotkeys = find_hotkeys_enabled_dict(host_filter=host_filter)

            if 'word' in request.form:
                if selectedTemplate in templates:
                    template_dir = get_registryCheckDict_directory()
                    report = ReportHotkeysEnabled()
                    output = generate_hotkey_docx(f"{template_dir}/{selectedTemplate}", report, hotkey_dict=hotkeys)
                    return Response(output, mimetype="text/docx",
                                    headers={
                                        "Content-disposition": "attachment; filename={0}.docx".format(report.name)})

    else:
        hotkeys = find_hotkeys_enabled_dict(host_filter=host_filter)

    return render_template('sysinfo/reports/registrycheck_hotkeys.html', hotkey_dict=hotkeys, form=form,
                           templates=templates, report_name="Hotkeys not disabled")


class ReportHotkeysEnabled(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="Hotkeys not disabled",
            category="HMI Hardening",
            tags=["Systemhardening", "StickyKeys", "MouseKeys", "ToggleKeys", "FilterKeys", "WindowsKey"],
            description='Report all hosts which does not disable hotkeys or some Windows key combinations (for the current user)!',
            views=[("view", url_for("sysinfo.report_hotkeys_enabled"))]
        )


####################################################################
# None Disabled Hotkeys and corresponding hosts
####################################################################
@sysinfo_bp.route('/report/LLMNR/', methods=['GET', 'POST'])
@login_required
def report_LLMNR_enabled():
    form = ConfigCheckReportForm()
    host_filter = []

    templates = get_configCheck_report_templates()
    form.TemplateFile.choices = [(template, template) for template in templates]

    cc = []
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

            cc = find_hosts_with_LLMNR(host_filter=host_filter)
            if 'excel' in request.form:
                output = generate_configchecks_excel(cc)
                return Response(output, mimetype="text/xlsx",
                                headers={"Content-disposition": "attachment; filename=Hosts-LLMNR_enabled.xlsx",
                                         "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})

            if 'word' in request.form:
                if selectedTemplate in templates:
                    template_dir = get_ConfigCheck_directory()
                    report = ReportLLMNREnabled()
                    output = generate_configcheck_docx(f"{template_dir}/{selectedTemplate}", report, checks=cc)
                    return Response(output, mimetype="text/docx",
                                    headers={
                                        "Content-disposition": "attachment; filename={0}.docx".format(report.name)})

    else:
        hotkeys = find_hotkeys_enabled_dict(host_filter=host_filter)

    return render_template('sysinfo/reports/configcheck.html', form=form, checks=cc,
                           templates=templates, report_name="LLMNR Enabled")


class ReportLLMNREnabled(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="Hosts with LLMNR enabled",
            category="Hardening",
            tags=["Systemhardening", "LLMNR"],
            description='Report all hosts which have LLMNR enabled',
            views=[("view", url_for("sysinfo.report_LLMNR_enabled"))]
        )
