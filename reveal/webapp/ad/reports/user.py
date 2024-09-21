from flask import render_template, Response, url_for, request
from flask_login import login_required

from reveal.webapp.ad import ad_bp
from reveal.core.reports import ReportInfo
from reveal.core.querries.ad import find_user_badpwcount_gt
from reveal.core.querries.ad import find_user_pw_expired
from reveal.core.querries.ad import find_user_pw_not_required
from reveal.core.querries.ad import find_user_sidhistory
from reveal.webapp.ad.forms.users import UserBadPwdCount
from reveal.webapp.ad.forms.users import UserDownload
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


####################################################################
# Get users with PW expired
####################################################################
@ad_bp.route('/reports/user/pwexpired/', methods=['GET','POST'])
@login_required
def report_aduser_pwexired():
    form = UserDownload()
    users = find_user_pw_expired()
    if request.method == 'POST' and form.validate_on_submit():
        if 'download' in request.form:
            output = generate_user_excel(user_list=users)
            return Response(output, mimetype="text/xlsx",
                            headers={"Content-disposition": "attachment; filename=ADUser-with-expired-pwds.xlsx",
                                     "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})

    return render_template('ad/reports/pwexpired_list.html', users=users, form=form,
                           report_name= 'List User with expired passwords.')


class ReportUserPWExpired(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name='List User expired passwords',
            category="User Management",
            tags=["User Management", "AD User", "password expired"],
            description='Report all domain user with a expired passwords',
            views=[("view", url_for("ad.report_aduser_pwexired"))]
        )


####################################################################
# Get users with PasswordNeverExpires
####################################################################
@ad_bp.route('/reports/user/pwneverexpired/', methods=['GET','POST'])
@login_required
def report_aduser_pwneverexired():
    form = UserDownload()
    users = find_user_pw_expired()
    if request.method == 'POST' and form.validate_on_submit():
        if 'download' in request.form:
            output = generate_user_excel(user_list=users)
            return Response(output, mimetype="text/xlsx",
                            headers={"Content-disposition": "attachment; filename=ADUser-with-pw-never-expired.xlsx",
                                     "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})

    return render_template('ad/reports/pwneverexpires_list.html', users=users, form=form,
                           report_name= 'List User which have PasswordNeverExpires set.')


class ReportUserPWNeverExpires(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name='List User which have attribute PasswordNeverExpires set',
            category="User Management",
            tags=["User Management", "AD User", "password never expires"],
            description='Report all domain user which have attribute PasswordNeverExpires set',
            views=[("view", url_for("ad.report_aduser_pwneverexired"))]
        )


####################################################################
# Get users with PasswordNotRequired
####################################################################
@ad_bp.route('/reports/user/pwnnotrequired/', methods=['GET','POST'])
@login_required
def report_aduser_pwnotrequired():
    form = UserDownload()
    users = find_user_pw_not_required()
    if request.method == 'POST' and form.validate_on_submit():
        if 'download' in request.form:
            output = generate_user_excel(user_list=users)
            return Response(output, mimetype="text/xlsx",
                            headers={"Content-disposition": "attachment; filename=ADUser-with-pw-not-required.xlsx",
                                     "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})

    return render_template('ad/reports/pwnotrequired_list.html', users=users, form=form,
                           report_name= 'List User which have PasswordNotRequired set.')


class ReportUserPWnotRequired(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name='List User which have attribute PasswordNotRequired set',
            category="User Management",
            tags=["User Management", "AD User", "password not required"],
            description='Report all domain user which have attribute PasswordNotRequired set',
            views=[("view", url_for("ad.report_aduser_pwnotrequired"))]
        )



####################################################################
# Get users with PasswordNotRequired
####################################################################
@ad_bp.route('/reports/user/sidhistory/', methods=['GET','POST'])
@login_required
def report_aduser_sidhistory():
    form = UserDownload()
    users = find_user_sidhistory()
    if request.method == 'POST' and form.validate_on_submit():
        if 'download' in request.form:
            output = generate_user_excel(user_list=users)
            return Response(output, mimetype="text/xlsx",
                            headers={"Content-disposition": "attachment; filename=ADUser-with-SID-history",
                                     "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})

    return render_template('ad/reports/user_with_sidhistory.html', users=users, form=form,
                           report_name= 'List User which have PasswordNotRequired set.')


class ReportUserSIDHistory(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name='List User which have a SID History',
            category="User Management",
            tags=["User Management", "AD User", "SID History"],
            description='List all domain user which have the attribute SIDHistory set',
            views=[("view", url_for("ad.report_aduser_pwnotrequired"))]
        )
