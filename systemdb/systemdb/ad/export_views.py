from flask import render_template, abort, Response, redirect, url_for
from sqlalchemy import and_

from . import ad_bp

from ..core.ad_models import ADComputer, ADUser,ADDomain, ADPasswordPolicy, ADDomainController, ADTrust, ADGroup
from .export_func import generate_computer_excel, generate_user_excel


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
    dc_list = ADDomainController.query.filter(ADDomainController.Domain_id == domain.id).all()
    policy_list = ADPasswordPolicy.query.filter(ADPasswordPolicy.Domain_id == domain.id).all()
    num_comp = ADComputer.query.filter(ADComputer.Domain_id == domain.id).count()
    num_users = ADUser.query.filter(ADUser.Domain_id == domain.id).count()
    num_groups = ADGroup.query.filter(ADGroup.Domain_id == domain.id).count()
    domadmins = ADGroup.query.filter(and_(ADGroup.Domain_id == domain.id, ADGroup.SamAccountName == "Domain Admins")).first()
    num_domadmins = len([m for m in domadmins.Members if domadmins is not None ])
    entadmins = ADGroup.query.filter(and_(ADGroup.Domain_id == domain.id, ADGroup.SamAccountName == "Enterprise Admins")).first()
    num_entadmins = len([m for m in entadmins.Members if entadmins is not None])
    schemaadmins = ADGroup.query.filter(and_(ADGroup.Domain_id == domain.id, ADGroup.SamAccountName == "Schema Admins")).first()
    num_schemaadmins = len([m for m in schemaadmins.Members if schemaadmins is not None])
    trusts = ADTrust.query.filter(ADTrust.Domain_id == domain.id).all()
    return render_template('addomain_details.html', domain=domain, dc_list=dc_list, policy_list=policy_list,
                           num_comp=num_comp, num_groups=num_groups, num_users=num_users, trusts=trusts,
                           num_domadmins=num_domadmins, domadmin_id=domadmins.id,
                           num_entadmins=num_entadmins, entadmin_id=entadmins.id,
                           num_schemaadmins=num_schemaadmins, schemaadmin_id=schemaadmins.id)

