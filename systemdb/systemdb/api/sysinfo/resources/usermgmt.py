from http import HTTPStatus
from flask.views import MethodView
from flask_smorest import Blueprint

from ..schemas.responses.usermgmt import UserGroupAssignment
from ....sysinfo.reports.usermgmt import get_direct_domainuser_assignments

blp = Blueprint('SysinfoCollector - Usermanagement', 'sysinfo_usermgmt_api' , url_prefix='/api/sysinfo',
                           description="Review users, groups, membership and assignments.")


@blp.route("/usermgmt/assignments/domainuser-in-group/")
class DirectUserAssignmentList(MethodView):

    @blp.doc(description="Return a list of domain users that area directly assigned to a local group.",
             summary="Find domain users that area directly assigned to a local group"
             )
    @blp.response(HTTPStatus.OK.value, UserGroupAssignment(many=True))
    def get(self):
        members = get_direct_domainuser_assignments()
        result = []
        for m in members:
            host, group, user = m
            u = UserGroupAssignment()
            u.Host = host
            u.Group = group
            u.User = user
            result.append(u)
        return result