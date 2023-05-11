from flask import render_template

from ..core.ad_models import ADDomain, ADTrust, ADDomainController, ADPasswordPolicy, ADUser, ADGroup, ADComputer
from sqlalchemy import and_
from . import ad_bp


@ad_bp.route('/ad/domains', methods=['GET'])
def domain_list():
    domains = ADDomain.query.all()
    return render_template('addomain_list.html', domains=domains)

@ad_bp.route('/ad/domain/<int:id>', methods=['GET'])
def domain_detail(id):
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
    dnsadmins = ADGroup.query.filter(and_(ADGroup.Domain_id == domain.id, ADGroup.SamAccountName == "DNSAdmins")).first()
    trusts = ADTrust.query.filter(ADTrust.Domain_id == domain.id).all()
    return render_template('addomain_details.html', domain=domain, dc_list=dc_list, policy_list=policy_list,
                           num_comp=num_comp, num_groups=num_groups, num_users=num_users, trusts=trusts,
                           num_domadmins=num_domadmins, domadmin_id=domadmins.id,
                           num_entadmins=num_entadmins, entadmin_id=entadmins.id,
                           num_schemaadmins=num_schemaadmins, schemaadmin_id=schemaadmins.id)

@ad_bp.route('/ad/trusts', methods=['GET'])
def trust_list():
    trusts = ADTrust.query.all()
    return render_template('adtrust_list.html', trusts=trusts)

