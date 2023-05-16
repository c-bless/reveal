from flask import render_template, abort, Response, redirect, url_for
from sqlalchemy import and_

from . import ad_bp

from ..core.ad_models import ADComputer, ADUser,ADDomain, ADPasswordPolicy, ADDomainController, ADTrust, ADGroup, ADGroupMember
from .export_func import generate_computer_excel, generate_user_excel
from .export_func import create_user_worksheet, create_computer_worksheet,create_trust_worksheet, create_dc_worksheet,create_domain_worksheet

import xlsxwriter
from io import StringIO, BytesIO

@ad_bp.route('/ad/computer/export/excel/', methods=['GET'])
def export_computer_excel():
    computer_list = ADComputer.query.all()

    output = generate_computer_excel(computer_list=computer_list)

    return Response(output, mimetype="text/xlsx",
                    headers={"Content-disposition": "attachment; filename=ad-computer.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })

    return redirect(url_for('ad.computer_list'))

@ad_bp.route('/ad/users/export/excel/', methods=['GET'])
def export_user_excel():
    user_list = ADUser.query.all()

    output = generate_user_excel(user_list=user_list)

    return Response(output, mimetype="text/xlsx",
                    headers={"Content-disposition": "attachment; filename=ad-user.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })

    return redirect(url_for('ad.user_list'))




@ad_bp.route('/ad/domain/<int:id>/export', methods=['GET'])
def domain_export_excel(id):
    domain = ADDomain.query.get_or_404(id)

    output = BytesIO()
    workbook = xlsxwriter.Workbook(output, {"in_memory": True})

    print("domain/pw policies")
    policy_list = ADPasswordPolicy.query.filter(ADPasswordPolicy.Domain_id == domain.id).all()
    domain_worksheet = create_domain_worksheet(workbook=workbook, domain=domain, policy_list=policy_list)
    print ("user")
    user_list = ADUser.query.filter(ADUser.Domain_id == domain.id).all()
    user_worksheet = create_user_worksheet(workbook=workbook, user_list=user_list)
    print("computer")
    computer_list= ADComputer.query.filter(ADComputer.Domain_id == domain.id).all()
    computer_worksheet = create_computer_worksheet(workbook=workbook, computer_list=computer_list)
    print("dc")
    dc_list = ADDomainController.query.filter(ADDomainController.Domain_id == domain.id).all()
    dc_worksheet = create_dc_worksheet(workbook=workbook, dc_list=dc_list)
    print("trust")
    trust_list = ADTrust.query.filter(ADTrust.Domain_id == domain.id).all()
    trust_worksheet = create_trust_worksheet(workbook=workbook, trust_list=trust_list)

    # Close the workbook before streaming the data.
    workbook.close()

    # Rewind the buffer.
    output.seek(0)

    return Response(output, mimetype="text/xlsx",
                    headers={"Content-disposition": "attachment; filename=ad-domain.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })


    return redirect(url_for('ad.computer_detail',id=id))

