from flask import render_template

from ..core.model import ADDomain, ADForest, ADTrust, ADUser, ADGroup, ADComputer, ADDomainController, ADForestGlobalCatalog, ADForestSite

from . import ad_bp


@ad_bp.route('/ad/users', methods=['GET'])
def user_list():
    users = ADUser.query.all()
    return render_template('aduser_list.html', users=users)


@ad_bp.route('/ad/user/<int:id>', methods=['GET'])
def user_detail(id):
    user = ADUser.query.get_or_404(id)
    return render_template('aduser_details.html', user=user)


@ad_bp.route('/ad/groups', methods=['GET'])
def groups_list():
    groups = ADGroup.query.all()
    return render_template('adgroup_list.html', groups=groups)


@ad_bp.route('/ad/group/<int:id>', methods=['GET'])
def group_detail(id):
    group = ADGroup.query.get_or_404(id)
    return render_template('adgroup_details.html', group=group)
