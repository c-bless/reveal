from flask import render_template

from ..core.model import ADDomain, ADForest, ADTrust, ADUser, ADGroup, ADComputer

from . import ad_bp
from flask import make_response

@ad_bp.route('/ad/domains', methods=['GET'])
def domain_list():
    domains = ADDomain.query.all()
    return render_template('addomain_list.html', domains=domains)

@ad_bp.route('/ad/domain/<int:id>', methods=['GET'])
def domain_detail(id):
    domain = ADDomain.query.get_or_404(id)
    return render_template('addomain_details.html', domain=domain)


@ad_bp.route('/ad/forests', methods=['GET'])
def forest_list():
    forests = ADForest.query.all()
    return render_template('adforest_list.html', forests=forests)


@ad_bp.route('/ad/forests', methods=['GET'])
def trust_list():
    trusts = ADTrust.query.all()
    return render_template('adtrust_list.html', trusts=trusts)


@ad_bp.route('/ad/users', methods=['GET'])
def user_list():
    users = ADUser.query.all()
    return render_template('aduser_list.html', users=users)



@ad_bp.route('/ad/groups', methods=['GET'])
def groups_list():
    groups = ADGroup.query.all()
    return render_template('adgroup_list.html', groups=groups)


@ad_bp.route('/ad/group/<int:id>', methods=['GET'])
def group_detail(id):
    group = ADGroup.query.get_or_404(id)
    return render_template('adgroup_details.html', group=group)


@ad_bp.route('/ad/computer', methods=['GET'])
def computer_list():
    computer_list = ADComputer.query.all()
    return render_template('adcomputer_list.html', computer_list=computer_list)




