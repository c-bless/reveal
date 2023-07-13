from flask import render_template
from flask_login import login_required

from webapp.systemdb.sysinfo import sysinfo_bp

from webapp.systemdb.models.sysinfo import Host, Group, User


@sysinfo_bp.route('/groups/<int:id>', methods=['GET'])
@login_required
def group_detail(id):
    group = Group.query.get_or_404(id)
    host = Host.query.get_or_404(group.Host_id)
    return render_template("group_details.html", group=group, host=host)


@sysinfo_bp.route('/users/<int:id>', methods=['GET'])
@login_required
def user_detail(id):
    user = User.query.get_or_404(id)
    host = Host.query.get_or_404(user.Host_id)
    return render_template("user_details.html", user=user, host=host)

