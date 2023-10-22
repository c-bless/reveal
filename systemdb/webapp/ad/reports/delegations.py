from flask import render_template, Response, url_for, request
from flask_login import login_required
from sqlalchemy import and_

from systemdb.webapp.ad import ad_bp
from systemdb.core.reports import ReportInfo

from systemdb.core.export.excel.ad import generate_computer_excel
from systemdb.core.models.activedirectory import ADComputer, ADSPN, ADDomain
from systemdb.core.querries.ad import find_computer_with_Unconstraint_Delegation
from systemdb.webapp.ad.forms.computer import ADComputerByUnconstraintDelegation

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

