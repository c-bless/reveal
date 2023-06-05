from http import HTTPStatus
from flask.views import MethodView
from flask_smorest import Blueprint

from ....models.sysinfo import Host, Group
from ..schemas.responses.hosts import HostSchema
import datetime

blp = Blueprint('SysinfoCollector - Reports', 'sysinfo_reports_api' , url_prefix='/api/sysinfo/reports',
                description="Report results of configuration reviews of hosts collected via sysinfo-collector scripts.")


#####################################################################################
# Winlogon with password
#####################################################################################
@blp.route("/Winlogon/")
class HostListWinlogonReportResource(MethodView):

    @blp.doc(description="Returns the hosts which have the autologon password (DefaultPassword) in Winlogon Hive.",
             summary="Find all hosts with DefaultPassword in Winlogon hive"
             )
    @blp.response(HTTPStatus.OK.value, HostSchema(many=True))
    def get(self):
        return Host.query.filter(Host.DefaultPassword != "").all()

#####################################################################################
# Last update > n days
#####################################################################################
@blp.route("/LastUpdate/<int:days>")
class HostListLastUpdateReportResource(MethodView):

    @blp.doc(description="Returns the hosts which have not been updated for a specified amount of days.",
             summary="Find all hosts which have not been updated for a specified amount of days."
             )
    @blp.response(HTTPStatus.OK.value, HostSchema(many=True))
    def get(self, days):
        now = datetime.datetime.now()
        delta = now - datetime.timedelta(days=days)
        print(delta)
        return Host.query.filter(Host.LastUpdate <= delta).all()

#####################################################################################
# Hosts with PowerShell version 2.0
#####################################################################################
@blp.route("/PS2/")
class HostListPS2ReportResource(MethodView):

    @blp.doc(description="Returns the hosts with PowerShell version 2.0 installed.",
             summary="Find all hosts with PowerShell version 2.0 installed."
             )
    @blp.response(HTTPStatus.OK.value, HostSchema(many=True))
    def get(self):
        return Host.query.filter(Host.PS2Installed == "True").all()

#####################################################################################
# Hosts with SMBv1 enabled
#####################################################################################
@blp.route("/SMBv1/")
class HostListSMBv1ReportResource(MethodView):

    @blp.doc(description="Returns the hosts with SMBv1 enabled.",
             summary="Find all hosts with SMBv1 enabled."
             )
    @blp.response(HTTPStatus.OK.value, HostSchema(many=True))
    def get(self):
        return Host.query.filter(Host.SMBv1Enabled == "True").all()

#####################################################################################
# Hosts with WSH enabled
#####################################################################################
@blp.route("/WSH-enabled/")
class HostListWSHReportResource(MethodView):

    @blp.doc(description="Returns the hosts with WSH enabled.",
             summary="Find all hosts with WSH enabled."
             )
    @blp.response(HTTPStatus.OK.value, HostSchema(many=True))
    def get(self):
        return Host.query.filter(Host.WSHEnabled == "Enabled").all()

#####################################################################################
# Hosts with WSH remote enabled
#####################################################################################
@blp.route("/WSH-remote/")
class HostListWSHRemoteReportResource(MethodView):

    @blp.doc(description="Returns the hosts with WSH remote enabled.",
             summary="Find all hosts with WSH remote enabled."
             )
    @blp.response(HTTPStatus.OK.value, HostSchema(many=True))
    def get(self):
        return Host.query.filter(Host.WSHRemote == "Enabled").all()

#####################################################################################
# Hosts with "Domain Admins" in local admin group
#####################################################################################
@blp.route("/domainadmins/")
class HostListDomainAdminsReportResource(MethodView):

    @blp.doc(description="Returns the hosts with 'Domain Admins' in local admin group.",
             summary="Find all hosts with 'Domain Admins' in local admin group."
             )
    @blp.response(HTTPStatus.OK.value, HostSchema(many=True))
    def get(self):
        groups = Group.query.filter(Group.SID == "S-1-5-32-544").all()
        host_ids = []
        for g in groups:
            for m in g.Members:
                if m.SID.endswith("-512"):
                    host_ids.append(g.Host_id)
        return Host.query.filter(Host.id.in_(host_ids)).all()