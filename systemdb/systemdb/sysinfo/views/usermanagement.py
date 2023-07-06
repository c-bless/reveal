from flask import render_template, url_for, request, Response
from sqlalchemy import desc,and_

from .. import sysinfo_bp

from ...models.sysinfo import Host, Group, User


@sysinfo_bp.route('/groups/<int:id>', methods=['GET'])
def group_detail(id):
    group = Group.query.get_or_404(id)
    host = Host.query.get_or_404(group.Host_id)
    return render_template("group_details.html", group=group, host=host)


@sysinfo_bp.route('/users/<int:id>', methods=['GET'])
def user_detail(id):
    user = User.query.get_or_404(id)
    host = Host.query.get_or_404(user.Host_id)
    return render_template("user_details.html", user=user, host=host)

