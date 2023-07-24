from flask import render_template
from flask_login import login_required

from systemdb.core.models.activedirectory import ADUser
from systemdb.core.models.activedirectory import ADGroup
from systemdb.core.models.activedirectory import ADDomain

from systemdb.webapp.ad import ad_bp


@ad_bp.route('/ad/users', methods=['GET'])
@login_required
def user_list():
    users = ADUser.query.all()
    return render_template('aduser_list.html', users=users)


@ad_bp.route('/ad/views/<int:id>/users', methods=['GET'])
@login_required
def user_by_domain_list(id):
    users = ADUser.query.filter(ADUser.Domain_id == id)
    return render_template('aduser_list.html', users=users)


@ad_bp.route('/ad/user/<int:id>', methods=['GET'])
@login_required
def user_detail(id):
    user = ADUser.query.get_or_404(id)
    return render_template('aduser_details.html', user=user)


@ad_bp.route('/ad/groups', methods=['GET'])
@login_required
def groups_list():
    groups = ADGroup.query.all()
    return render_template('adgroup_list.html', groups=groups)


@ad_bp.route('/ad/views/<int:id>/groups', methods=['GET'])
@login_required
def groups_by_domain_list(id):
    groups = ADGroup.query.filter(ADGroup.Domain_id==id).all()
    return render_template('adgroup_list.html', groups=groups)


@ad_bp.route('/ad/group/<int:id>', methods=['GET'])
@login_required
def group_detail(id):
    group = ADGroup.query.get_or_404(id)
    domain = ADDomain.query.filter(ADDomain.id == group.Domain_id).first()
    return render_template('adgroup_details.html', group=group, domain=domain)
