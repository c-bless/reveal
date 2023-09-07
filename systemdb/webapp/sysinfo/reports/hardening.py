from flask import render_template, Response, url_for
from flask_login import login_required

from systemdb.webapp.sysinfo import sysinfo_bp
from systemdb.core.querries.hardening import find_hotkeys_enabled_dict
from systemdb.core.querries.hardening import find_hotkeys_enabled_list
from systemdb.core.export.excel.checks import generate_registrychecks_excel
from systemdb.core.reports import ReportInfo


####################################################################
# None Disabled Hotkeys and corresponding hosts
####################################################################
@sysinfo_bp.route('/report/hotkeys/', methods=['GET'])
@login_required
def report_hotkeys_enabled():
    hotkeys = find_hotkeys_enabled_dict()
    return render_template('report_registrycheck_hotkeys.html', hotkey_dict=hotkeys,
                           download_url=url_for("sysinfo.report_hotkeys_enabled_download"))


@sysinfo_bp.route('/report/hotkeys/excel/', methods=['GET'])
@login_required
def report_hotkeys_enabled_download():
    hotkeys = find_hotkeys_enabled_list()
    output = generate_registrychecks_excel(hotkeys)
    return Response(output, mimetype="text/xlsx",
                    headers={"Content-disposition": "attachment; filename=missing-disabled-hostkeys.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })


class ReportHotkeysEnabled(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="Hotkeys not disabled",
            category="HMI Hardening",
            tags=["Systemhardening", "StickyKeys", "MouseKeys", "ToggleKeys", "FilterKeys", "WindowsKey"],
            description='Report all hosts which does not disable hotkeys or some Windows key combinations (for the current user)!',
            views=[("view", url_for("sysinfo.report_hotkeys_enabled"))]
        )