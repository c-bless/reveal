from flask import render_template
from flask_login import login_required
from sqlalchemy import and_

from systemdb.core.models.activedirectory import ADDomain, ADTrust, ADDomainController, ADPasswordPolicy, \
    ADUser, ADGroup, ADComputer, ADGroupMember
from systemdb.webapp.ad import ad_bp


@ad_bp.route('/ad/domains', methods=['GET'])
@login_required
def domain_list():
    domains = ADDomain.query.all()
    return render_template('addomain_list.html', domains=domains)


@ad_bp.route('/ad/domain/<int:id>', methods=['GET'])
@login_required
def domain_detail(id):
    domain = ADDomain.query.get_or_404(id)
    dc_list = ADDomainController.query.filter(ADDomainController.Domain_id == domain.id).all()
    policy_list = ADPasswordPolicy.query.filter(ADPasswordPolicy.Domain_id == domain.id).all()
    num_comp = ADComputer.query.filter(ADComputer.Domain_id == domain.id).count()
    num_users = ADUser.query.filter(ADUser.Domain_id == domain.id).count()
    num_groups = ADGroup.query.filter(ADGroup.Domain_id == domain.id).count()
    domadmins = ADGroup.query.filter(and_(ADGroup.Domain_id == domain.id, ADGroup.SamAccountName == "Domain Admins")).first()
    if domadmins is not  None:
        num_domadmins = ADGroupMember.query.filter(ADGroupMember.Group_id == domadmins.id).count()
    else:
        num_domadmins = 0
    trusts = ADTrust.query.filter(ADTrust.Domain_id == domain.id).all()
    return render_template('addomain_details.html', domain=domain, dc_list=dc_list, policy_list=policy_list,
                           num_comp=num_comp, num_groups=num_groups, num_users=num_users, trusts=trusts,
                           num_domadmins=num_domadmins, domadmin_id=domadmins.id)


@ad_bp.route('/ad/trusts', methods=['GET'])
@login_required
def trust_list():
    trusts = ADTrust.query.all()
    return render_template('adtrust_list.html', trusts=trusts)

