from flask import render_template, Response, url_for, request
from flask_login import login_required
from sqlalchemy import and_

from reveal.webapp.ad import ad_bp
from reveal.core.reports import ReportInfo

from reveal.core.export.excel.ad import generate_computer_excel
from reveal.core.export.excel.ad import generate_user_excel
from reveal.core.models.activedirectory import ADComputer, ADSPN, ADDomain
from reveal.core.querries.ad import find_computer_with_Unconstraint_Delegation
from reveal.core.querries.ad import find_user_with_delegation
from reveal.webapp.ad.forms.computer import ADComputerByUnconstraintDelegation
from reveal.webapp.ad.forms.computer import ADUserByUnconstraintDelegation


####################################################################
# Computer with delegations report
####################################################################
@ad_bp.route('/reports/computer/with-delegation/', methods=['GET', 'POST'])
@login_required
def computer_by_delegation():
    form = ADComputerByUnconstraintDelegation()
    computer_list = find_computer_with_Unconstraint_Delegation()

    if 'download' in request.form:
        output = generate_computer_excel(computer_list=computer_list)
        return Response(output, mimetype="text/xslx",
                        headers={"Content-disposition": "attachment; filename=computer_by_delegation.xlsx",
                                 "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})

    return render_template('ad/reports/computer_by_delegation.html', computer_list=computer_list,
                           form=form, report_name= 'Computer by Delegation')


class ReportComputerByUnconstraintDelegation(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name='List computers with "Unconstraint Delegation"',
            category="Computer",
            tags=["TrustedForDelegation","Unconstraint Delegation"],
            description='Report all computer with "Unconstraint Delegation"',
            views=[("view", url_for("ad.computer_by_delegation"))]
        )



####################################################################
# Computer with delegations report
####################################################################
@ad_bp.route('/reports/user/with-delegation/', methods=['GET', 'POST'])
@login_required
def user_by_delegation():
    form = ADUserByUnconstraintDelegation()
    user_list = find_user_with_delegation()

    if 'download' in request.form:
        output = generate_user_excel(user_list=user_list)
        return Response(output, mimetype="text/xslx",
                        headers={"Content-disposition": "attachment; filename=computer_by_delegation.xlsx",
                                 "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})

    return render_template('ad/reports/user_by_delegation.html', users=user_list,
                           form=form, report_name= 'User by Delegation')


class ReportComputerByUnconstraintDelegation(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name='List users with "Kerberos Delegations"',
            category="User",
            tags=["TrustedForDelegation", "TrustedToAuthForDelegation", "Kerberos Delegation"],
            description='Report all users with "Kerberos Delegation"',
            views=[("view", url_for("ad.user_by_delegation"))]
        )

