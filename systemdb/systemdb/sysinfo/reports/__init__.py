from flask import url_for

class ReportInfo(object):

    _name =""
    _category =""
    _tags = []
    _description = ""
    _views = []

    def __init__(self):
        super().__init__()

    def initWithParams(self, name="", category="", tags=[], description="", views=[]):
        super().__init__()
        self._name = name
        self._category = category
        self._tags = tags
        self._description = description
        self._views = views

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self,name=""):
        self._name = name

    @property
    def category(self):
        return self._category

    @category.setter
    def category(self, category=""):
        self._category = category

    @property
    def tags(self):
        return self._tags

    @tags.setter
    def tags(self, tags=[]):
        self._tags = tags

    @property
    def description(self):
        return self._description

    @description.setter
    def description(self, description=""):
        self._description = description

    @property
    def views(self):
        return self._views

    @views.setter
    def views(self, views= []):
        self._views = views


    def __str__(self):
        return str(self._name)



def get_report_list():
    report_plugin_list = []

    from .admins import ReportDomAdminMemberOfLocalAdmin, ReportAutologonIsLocalAdmin
    report_plugin_list.append(ReportDomAdminMemberOfLocalAdmin())
    report_plugin_list.append(ReportAutologonIsLocalAdmin())

    from .powershell import ReportPS2Istalled
    report_plugin_list.append(ReportPS2Istalled())

    from .updates import ReportLastUpdate, ReportEOL
    report_plugin_list.append(ReportLastUpdate())
    report_plugin_list.append(ReportEOL())

    from .winlogon import ReportPWInWinlogon
    report_plugin_list.append(ReportPWInWinlogon())

    from .smb import ReportSMBv1
    report_plugin_list.append(ReportSMBv1())

    from .wsh import ReportWSHEnabled, ReportWSHRemoteEnabled
    report_plugin_list.append(ReportWSHEnabled())
    report_plugin_list.append(ReportWSHRemoteEnabled())

    from .wsus import ReportWSUSHttp
    report_plugin_list.append(ReportWSUSHttp())

    from .usermgmt import ReportDirectDomainUserAssignment
    report_plugin_list.append(ReportDirectDomainUserAssignment())

    from .services import ReportUQSP, ReportServiceByPermission, ReportServiceByUsercontext
    report_plugin_list.append(ReportUQSP())
    report_plugin_list.append(ReportServiceByPermission())
    report_plugin_list.append(ReportServiceByUsercontext())

    from .printers import ReportFilePrinterInstalled
    report_plugin_list.append(ReportFilePrinterInstalled())

    return report_plugin_list