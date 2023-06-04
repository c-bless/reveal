from flask_restful import Resource

from ... import api
from ....models.sysinfo import Host, Group
from ...schema.sysinfo.hosts import hosts_schema, host_schema
import datetime

#####################################################################################
# Winlogon with password
#####################################################################################
class HostListWinlogonReportResource(Resource):

    def get(self):
        """
           Returns the hosts with DefaultPassword in Winlogon Hive.

           ---
           tags:
             - reports
           responses:
             200:
               description: list of affected hosts

           """
        hosts = Host.query.filter(Host.DefaultPassword != "").all()
        return hosts_schema.dump(hosts)


api.add_resource(HostListWinlogonReportResource, '/sysinfo/report/winlogon/', endpoint='sysinfo_report_winlogon')


#####################################################################################
# Last update > n days
#####################################################################################
class HostListLastUpdateReportResource(Resource):

    def get(self, days):
        """
           Returns the hosts with have not been updated

           ---
           tags:
             - reports
           parameters:
             - in: path
               name: days
               type: integer
               required: true
           responses:
             200:
               description: list of affected hosts

           """
        now = datetime.datetime.now()
        delta = now - datetime.timedelta(days=days)
        hosts = Host.query.filter(Host.LastUpdate <= delta).all()
        return hosts_schema.dump(hosts)


api.add_resource(HostListLastUpdateReportResource, '/sysinfo/report/lastupdate/<int:days>', endpoint='sysinfo_report_lastupdate')


#####################################################################################
# Hosts with PowerShell version 2.0
#####################################################################################
class HostListPS2ReportResource(Resource):

    def get(self):
        """
           Returns the hosts with PowerShell version 2.0 installed.

           ---
           tags:
             - reports
           responses:
             200:
               description: list of affected hosts

           """
        hosts = Host.query.filter(Host.PS2Installed == "True").all()
        return hosts_schema.dump(hosts)


api.add_resource(HostListPS2ReportResource, '/sysinfo/report/PS2/', endpoint='sysinfo_report_ps2')


#####################################################################################
# Hosts with SMBv1 enabled
#####################################################################################
class HostListSMBv1ReportResource(Resource):

    def get(self):
        """
           Returns the hosts with SMBv1 enabled.

           ---
           tags:
             - reports
           responses:
             200:
               description: list of affected hosts

           """
        hosts = Host.query.filter(Host.SMBv1Enabled == "True").all()
        return hosts_schema.dump(hosts)


api.add_resource(HostListSMBv1ReportResource, '/sysinfo/report/SMBv1/', endpoint='sysinfo_report_smbv1')


#####################################################################################
# Hosts with WSH enabled
#####################################################################################
class HostListWSHReportResource(Resource):

    def get(self):
        """
           Returns the hosts with WSH enabled.

           ---
           tags:
             - reports
           responses:
             200:
               description: list of affected hosts

           """
        hosts = Host.query.filter(Host.WSHEnabled == "Enabled").all()
        return hosts_schema.dump(hosts)


api.add_resource(HostListWSHReportResource, '/sysinfo/report/WSH-enabled/', endpoint='sysinfo_report_wsh_enabled')



#####################################################################################
# Hosts with WSH remote enabled
#####################################################################################
class HostListWSHRemoteReportResource(Resource):

    def get(self):
        """
           Returns the hosts with WSH remote enabled.

           ---
           tags:
             - reports
           responses:
             200:
               description: list of affected hosts

           """
        hosts = Host.query.filter(Host.WSHRemote == "Enabled").all()
        return hosts_schema.dump(hosts)


api.add_resource(HostListWSHRemoteReportResource, '/sysinfo/report/WSH-remote/', endpoint='sysinfo_report_wsh_remote')


#####################################################################################
# Hosts with "Domain Admins" in local admin group
#####################################################################################
class HostListDomainAdminsReportResource(Resource):

    def get(self):
        """
           Returns the hosts with "Domain Admins" in local admin group.

           ---
           tags:
             - reports
           responses:
             200:
               description: list of affected hosts

           """
        groups = Group.query.filter(Group.SID == "S-1-5-32-544").all()
        host_ids = []
        for g in groups:
            for m in g.Members:
                if m.SID.endswith("-512"):
                    host_ids.append(g.Host_id)
        hosts = Host.query.filter(Host.id.in_(host_ids)).all()
        return hosts_schema.dump(hosts)


api.add_resource(HostListDomainAdminsReportResource, '/sysinfo/report/domainadmins/', endpoint='sysinfo_report_domain_admins')
