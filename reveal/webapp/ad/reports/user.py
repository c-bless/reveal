from flask import render_template, Response, url_for, request
from flask_login import login_required

from reveal.webapp.ad import ad_bp
from reveal.core.reports import ReportInfo
from reveal.core.querries.ad import find_user_badpwcount_gt
from reveal.webapp.ad.forms.users import UserBadPwdCount
from reveal.core.export.excel.ad import generate_user_excel

####################################################################
# Get users with BadPwdCount
####################################################################
@ad_bp.route('/reports/user/badpwdcount/', methods=['GET','POST'])
@login_required
def report_aduser_badpwdcount():
    form = UserBadPwdCount()

    if request.method == 'POST' and form.validate_on_submit():
        n = form.n.data

        print(f"N = {n}")
        users = find_user_badpwcount_gt(n=n)
        if 'download' in request.form:
            output = generate_user_excel(user_list=users)
            return Response(output, mimetype="text/xlsx",
                            headers={"Content-disposition": "attachment; filename=ADUser-with-BadPwdCount.xlsx",
                                     "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})
    else:
        users = find_user_badpwcount_gt(n=5)
    return render_template('ad/reports/badpwdcount_list.html', users=users, form=form,
                           report_name= 'List User with BadPwCount >= n')


class ReportUserBadPwCountGtN(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name='List User with BadPwdCount >= n',
            category="User Management",
            tags=["User Management", "AD User", "BadPwCount"],
            description='Report all domain user with a BadPwCount of "n" or greater. Default for n=5.',
            views=[("view", url_for("ad.report_aduser_badpwdcount"))]
        )

