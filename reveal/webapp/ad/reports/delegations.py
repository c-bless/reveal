from flask import render_template, Response, url_for, request
from flask_login import login_required
from sqlalchemy import and_

from reveal.webapp.ad import ad_bp
from reveal.core.reports import ReportInfo

from reveal.core.export.excel.ad import generate_computer_excel
from reveal.core.export.excel.ad import generate_user_excel
from reveal.core.models.activedirectory import ADComputer, ADSPN, ADDomain
from reveal.core.querries.ad import find_computer_with_Unconstraint_Delegation
from reveal.core.querries.ad import find_user_with_unconstraint_delegation
from reveal.core.querries.ad import find_user_with_constraint_delegation
from reveal.webapp.ad.forms.computer import ADComputerByUnconstraintDelegation
from reveal.webapp.ad.forms.users import ADUserByConstraintDelegation
from reveal.webapp.ad.forms.users import ADUserByUnconstraintDelegation


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
# User with constraint delegations report
####################################################################
@ad_bp.route('/reports/user/unconstraintdelegation/', methods=['GET', 'POST'])
@login_required
def user_by_unconstraint_delegation():
    form = ADUserByUnconstraintDelegation()
    user_list = find_user_with_unconstraint_delegation()

    if 'download' in request.form:
        output = generate_user_excel(user_list=user_list)
        return Response(output, mimetype="text/xslx",
                        headers={"Content-disposition": "attachment; filename=user_unconstraintdelegation.xlsx",
                                 "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})

    return render_template('ad/reports/user_by_unconstraint_delegation.html', users=user_list,
                           form=form, report_name= 'User by Delegation')


class ReportUserByUnconstraintDelegation(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name='List users with "Unconstraint Kerberos Delegations"',
            category="User",
            tags=["TrustedToAuthForDelegation", "Unconstraint Kerberos Delegation"],
            description='Report all users with "Unconstraint Kerberos Delegation"',
            views=[("view", url_for("ad.user_by_unconstraint_delegation"))]
        )


####################################################################
# User with constraint delegations report
####################################################################
@ad_bp.route('/reports/user/constraintdelegation/', methods=['GET', 'POST'])
@login_required
def user_by_constraint_delegation():
    form = ADUserByConstraintDelegation()
    user_list = find_user_with_constraint_delegation()

    if 'download' in request.form:
        output = generate_user_excel(user_list=user_list)
        return Response(output, mimetype="text/xslx",
                        headers={"Content-disposition": "attachment; filename=user_constraintdelegation.xlsx",
                                 "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})

    return render_template('ad/reports/user_by_constraint_delegation.html', users=user_list,
                           form=form, report_name= 'User by Delegation')


class ReportUserByConstraintDelegation(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name='List users with "Constraint Kerberos Delegations"',
            category="User",
            tags=["TrustedToAuthForDelegation", "Constraint Kerberos Delegation"],
            description='Report all users with "Constraint Kerberos Delegation"',
            views=[("view", url_for("ad.user_by_constraint_delegation"))]
        )

