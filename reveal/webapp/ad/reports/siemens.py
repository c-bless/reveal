from flask import render_template, Response, url_for, request
from flask_login import login_required

from reveal.webapp.ad import ad_bp
from reveal.core.reports import ReportInfo
from reveal.core.export.excel.ad_groupmembers import generate_ad_groupmembers_excel
from reveal.core.querries.ad import find_SIMATIC_groups
from reveal.webapp.ad.forms.groups import GroupDownload


####################################################################
# Members in Domain Admins groups
####################################################################
@ad_bp.route('/reports/members/SIMATIC/', methods=['GET', 'POST'])
@login_required
def groupmembers_simatic():
    """
    Creates a list of groups with 'SIMATIC' in their names (e.g., GG_SIMATIC_HMI).

    :return: HTML with result table or an Excel spreadsheet is post parameter 'download' is present.
    """
    form = GroupDownload()
    groups = find_SIMATIC_groups()
    if request.method == 'POST' and form.validate_on_submit():
        if 'download' in request.form:
            output = generate_ad_groupmembers_excel(groups)
            return Response(output, mimetype="text/xlsx",
                            headers={"Content-disposition": "attachment; filename=groupmembers_SIMATIC_groups.xlsx",
                                     "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})
    return render_template('ad/reports/groupmembers_list.html', groups=groups, form=form,
                           report_name='GroupMembers "%SIMATIC" groups')


class ReportSIMATICGroups(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name='List members of "%SIMATIC%" groups',
            category="User Management",
            tags=["User Management", "SIMATIC", "SIEMENS", "GG_SIMATIC_HMI"],
            description='Report all members of of "SIMATIC" groups.',
            views=[("view", url_for("ad.groupmembers_simatic"))]
        )
