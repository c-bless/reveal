from flask import render_template, abort, Response, redirect, url_for
from sqlalchemy import and_

from . import ad_bp

from ..core.ad_models import ADComputer, ADUser,ADDomain, ADPasswordPolicy, ADDomainController, ADTrust, ADGroup, ADGroupMember
from .export_func import generate_computer_excel, generate_user_excel, generate_domain_excel


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
    user_list = ADUser.query.filter(ADUser.Domain_id == domain.id).all()
    computer_list= ADComputer.query.filter(ADComputer.Domain_id == domain.id).all()
    dc_list = ADDomainController.query.filter(ADDomainController.Domain_id == domain.id).all()
    policy_list = ADPasswordPolicy.query.filter(ADPasswordPolicy.Domain_id == domain.id).all()
    trust_list = ADTrust.query.filter(ADTrust.Domain_id == domain.id).all()

    num_groups = ADGroup.query.filter(ADGroup.Domain_id == domain.id).count()
    domadmins = ADGroup.query.filter(
        and_(ADGroup.Domain_id == domain.id, ADGroup.SamAccountName == "Domain Admins")).first()
    if domadmins is not None:
        num_domadmins = ADGroupMember.query.filter(ADGroupMember.Group_id == domadmins.id).count()
    else:
        num_domadmins = 0

    output = generate_domain_excel(domain=domain, user_list=user_list, computer_list=computer_list, dc_list=dc_list,
                                   trust_list=trust_list, policy_list=policy_list)

    return Response(output, mimetype="text/xlsx",
                    headers={"Content-disposition": "attachment; filename=ad-domain.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })


    return redirect(url_for('ad.computer_detail',id=id))

