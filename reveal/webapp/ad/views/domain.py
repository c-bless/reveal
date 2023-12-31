from flask import render_template
from flask_login import login_required
from sqlalchemy import and_

from reveal.core.models.activedirectory import ADDomain, ADTrust, ADDomainController, ADPasswordPolicy, \
    ADUser, ADGroup, ADComputer, ADGroupMember
from reveal.webapp.ad import ad_bp


@ad_bp.route('/ad/domains', methods=['GET'])
@login_required
def domain_list():
    domains = ADDomain.query.all()
    return render_template('ad/domain/addomain_list.html', domains=domains)


@ad_bp.route('/ad/domains/<int:id>', methods=['GET'])
@login_required
def domain_detail(id):
    domain = ADDomain.query.get_or_404(id)
    dc_list = ADDomainController.query.filter(ADDomainController.Domain_id == domain.id).all()
    policy_list = ADPasswordPolicy.query.filter(ADPasswordPolicy.Domain_id == domain.id).all()
    num_comp = ADComputer.query.filter(ADComputer.Domain_id == domain.id).count()
    num_users = ADUser.query.filter(ADUser.Domain_id == domain.id).count()
    num_groups = ADGroup.query.filter(ADGroup.Domain_id == domain.id).count()
    domadmins = ADGroup.query.filter(and_(ADGroup.Domain_id == domain.id, ADGroup.SID.ilike("%-512"))).first()
    domadmins_id = None
    if domadmins is not None:
        num_domadmins = ADGroupMember.query.filter(ADGroupMember.Group_id == domadmins.id).count()
        domadmins_id = domadmins.id
    else:
        num_domadmins = 0
    trusts = ADTrust.query.filter(ADTrust.Domain_id == domain.id).all()
    return render_template('ad/domain/addomain_details.html', domain=domain, dc_list=dc_list, policy_list=policy_list,
                           num_comp=num_comp, num_groups=num_groups, num_users=num_users, trusts=trusts,
                           num_domadmins=num_domadmins, domadmin_id=domadmins_id)

