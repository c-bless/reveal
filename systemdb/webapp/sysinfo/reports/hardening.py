from flask import render_template, Response, url_for
from flask_login import login_required

from systemdb.webapp.sysinfo import sysinfo_bp
from systemdb.core.querries.hardening import find_hotkeys_enabled
from systemdb.core.reports import ReportInfo


####################################################################
# None Disabled Hotkeys and corresponding hosts
####################################################################
@sysinfo_bp.route('/report/hotkeys/', methods=['GET'])
@login_required
def report_hotkeys_enabled():
    hotkeys = find_hotkeys_enabled()
    return render_template('report_registrycheck_hotkeys.html', hotkey_dict=hotkeys)


class ReportHotkeysEnabled(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="Hotkeys not disabled",
            category="HMI Hardening",
            tags=["Systemhardening", "StickyKeys", "MouseKeys", "ToggleKeys", "FilterKeys", "WindowsKey"],
            description='Report all hosts which does not disable hotkeys or some Windows key combinations (for the current user)!',
            views=[("view", url_for("sysinfo.report_hotkeys_enabled"))]
        )