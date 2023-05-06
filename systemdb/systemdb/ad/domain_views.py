from flask import render_template

from ..core.model import ADDomain, ADForest, ADTrust, ADUser, ADGroup, ADComputer, ADDomainController, ADForestGlobalCatalog, ADForestSite, ADPasswordPolicy

from . import ad_bp


@ad_bp.route('/ad/domains', methods=['GET'])
def domain_list():
    domains = ADDomain.query.all()
    return render_template('addomain_list.html', domains=domains)

@ad_bp.route('/ad/domain/<int:id>', methods=['GET'])
def domain_detail(id):
    domain = ADDomain.query.get_or_404(id)
    dc_list = ADDomainController.query.filter(ADDomainController.Domain == domain.DNSRoot).all()
    return render_template('addomain_details.html', domain=domain, dc_list=dc_list)

@ad_bp.route('/ad/trusts', methods=['GET'])
def trust_list():
    trusts = ADTrust.query.all()
    return render_template('adtrust_list.html', trusts=trusts)

