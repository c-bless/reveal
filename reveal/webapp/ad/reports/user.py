from flask import render_template, Response, url_for, request
from flask_login import login_required

from reveal.webapp.ad import ad_bp
from reveal.core.reports import ReportInfo
from reveal.core.querries.ad import find_user_badpwcount_gt


####################################################################
# Get users with BadPwdCount
####################################################################
@ad_bp.route('/reports/user/badpwdcount/<int:n>', methods=['GET'])
@login_required
def report_aduser_badpwdcount(n: int):
    users = find_user_badpwcount_gt(n)
    return render_template('ad/reports/badpwdcount_list.html', users=users,
                           report_name= 'List User with BadPwCount >= n')


class ReportUserBadPwCountGtN(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name='List User with BadPwdCount >= n',
            category=["User Management", "AD User", "BadPwCount"],
            description='Report all domain user with a BadPwCount of "n" or greater',
            views=[("view", url_for("ad.report_aduser_badpwdcount", n=5))]
        )

