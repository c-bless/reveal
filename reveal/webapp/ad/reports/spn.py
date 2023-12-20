from flask import render_template, Response, url_for, request
from flask_login import login_required
from sqlalchemy import and_

from reveal.webapp.ad import ad_bp
from reveal.core.reports import ReportInfo

from reveal.webapp.ad.forms.computer import ADComputerBySPNSearchForm
from reveal.core.export.excel.ad import generate_computer_excel
from reveal.core.models.activedirectory import ADComputer, ADSPN, ADDomain


####################################################################
# Computer with SPN report
####################################################################
@ad_bp.route('/reports/computer/by-spn/', methods=['GET', 'POST'])
@login_required
def computer_by_spn():
    form = ADComputerBySPNSearchForm()
    computer_list = []

    if request.method == 'POST':
        filters = []
        if form.validate_on_submit():
            spn = form.SPN.data
            invertSPN = form.InvertSPN.data

            domain = form.Domain.data
            invertDomain = form.InvertDomain.data

            if len(spn) > 0 :
                if not invertSPN:
                    filters.append(ADSPN.Name.ilike("%"+spn+"%"))
                else:
                    filters.append(ADSPN.Name.notilike("%"+spn+"%"))

            if len(domain) > 0:
                if not invertDomain:
                    spns = ADSPN.query.filter(and_(*filters)).join(ADComputer).join(
                        ADDomain).filter(ADDomain.Name.ilike("%"+domain+"%")).all()
                else:
                    spns = ADSPN.query.filter(and_(*filters)).join(ADComputer).join(
                        ADDomain).filter(ADDomain.Name.notilike("%" + domain + "%")).all()
            else:
                spns = ADSPN.query.filter(and_(*filters)).all()

            computer_ids = []
            computer_list = []

            for s in spns:
                c = s.Computer
                if c.id not in computer_ids:
                    computer_ids.append(c.id)
                    computer_list.append(c)

            if 'download' in request.form:
                output = generate_computer_excel(computer_list=computer_list)
                return Response(output, mimetype="text/xslx",
                                headers={"Content-disposition": "attachment; filename=computer_by_spn.xlsx",
                                         "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})

    return render_template('ad/reports/computer_by_spn.html', computer_list=computer_list,
                           form=form, report_name= 'Computer by SPN')


class ReportComputerBySPN(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name='List computers by SPN',
            category="Computer",
            tags=["Service Principal Name", "SPN"],
            description='Report all computer by SPN',
            views=[("view", url_for("ad.computer_by_spn"))]
        )

