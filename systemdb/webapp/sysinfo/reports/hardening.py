from flask import render_template, Response, url_for, request
from flask_login import login_required

from systemdb.webapp.sysinfo import sysinfo_bp
from systemdb.core.querries.hardening import find_hotkeys_enabled_dict
from systemdb.core.querries.hardening import find_hotkeys_enabled_list
from systemdb.core.export.excel.checks import generate_registrychecks_excel
from systemdb.core.models.sysinfo import Host
from systemdb.webapp.sysinfo.forms.report.ChecksReport import RegistryCheckReportForm

from systemdb.core.reports import ReportInfo


####################################################################
# None Disabled Hotkeys and corresponding hosts
####################################################################
@sysinfo_bp.route('/report/hotkeys/', methods=['GET','POST'])
@login_required
def report_hotkeys_enabled():
    form = RegistryCheckReportForm()
    host_filter = []

    if request.method == 'POST':
        filters = []
        if form.validate_on_submit():
            systemgroup = form.SystemGroup.data
            location = form.Location.data

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

            if 'excel' in request.form:
                hotkeys = find_hotkeys_enabled_list(host_filter=host_filter)
                output = generate_registrychecks_excel(hotkeys)
                return Response(output, mimetype="text/xlsx",
                                headers={"Content-disposition": "attachment; filename=missing-disabled-hostkeys.xlsx",
                                         "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})
            else:
                hotkeys = find_hotkeys_enabled_dict(host_filter=host_filter)
    else:
        hotkeys = find_hotkeys_enabled_dict(host_filter=host_filter)

    return render_template('sysinfo/reports/registrycheck_hotkeys.html', hotkey_dict=hotkeys, form=form,
                           report_name="Hotkeys not disabled")


class ReportHotkeysEnabled(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="Hotkeys not disabled",
            category="HMI Hardening",
            tags=["Systemhardening", "StickyKeys", "MouseKeys", "ToggleKeys", "FilterKeys", "WindowsKey"],
            description='Report all hosts which does not disable hotkeys or some Windows key combinations (for the current user)!',
            views=[("view", url_for("sysinfo.report_hotkeys_enabled"))]
        )