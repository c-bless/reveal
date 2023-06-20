from http import HTTPStatus
from flask.views import MethodView
from flask_smorest import Blueprint
from sqlalchemy import and_

from ....models.sysinfo import Host, Group, User
from ....models.eol import EoL
from ..schemas.responses.hosts import HostSchema
from ..schemas.responses.eol import EoLMatchSchema
from ..schemas.arguments.eol import EoLSearchSchema

from ..schemas.responses.usermgmt import UserGroupAssignment
from ....sysinfo.reports.usermgmt import get_direct_domainuser_assignments

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


#####################################################################################
# Matching host and End-of-Life entries
#####################################################################################
@blp.route("/wsus-http/")
class HostListWsusResource(MethodView):

    @blp.doc(description="Returns a list of hosts configured to use WSUS via http.",
             summary="Find all hosts configured for using WSUS vi http."
             )

    @blp.response(HTTPStatus.OK.value, HostSchema(many=True))
    def post(self):
        return Host.query.filter(Host.WUServer.like('http://%'))



#####################################################################################
# Autologin as admin user
#####################################################################################
@blp.route("/autologon-admin/")
class HostListAutologonAdminResource(MethodView):

    @blp.doc(description="Returns a list of hosts that use autologon with an administrative account.",
             summary="Find all hosts configured for using autologon with an administrative account."
             )

    @blp.response(HTTPStatus.OK.value, HostSchema(many=True))
    def post(self):
        result = []
        autologon_hosts = Host.query.filter(Host.AutoAdminLogon == 1).all()
        for h in autologon_hosts:
            defaultUser = h.DefaultUserName
            defaultDomain = h.DefaultDomain
            admins = Group.query.filter(and_( Group.SID == "S-1-5-32-544", Group.Host_id == h.id)).first()
            for m in admins.Members:
                if defaultDomain == m.Domain and defaultUser == m.Name:
                    result.append(h)
        return result


#####################################################################################
# Matching host and End-of-Life entries
#####################################################################################
@blp.route("/eol/")
class HostListEOLMatchResource(MethodView):

    @blp.doc(description="Returns the ......",
             summary="Find all ..."
             )
    @blp.response(HTTPStatus.OK.value, EoLMatchSchema)
    def post(self):
        eols = EoL.query.filter(EoL.EndOfService == True).all()
        build_numbers = [e.Build for e in eols]
        print (eols)
        print (build_numbers)
        hosts = Host.query.filter(Host.OSBuildNumber.in_(build_numbers)).all()
        print(hosts)

        return {}




#####################################################################################
# Domainusers that are directly assigned to local groups
#####################################################################################
@blp.route("/domainuser-in-group/")
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